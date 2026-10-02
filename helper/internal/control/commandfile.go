package control

import (
	"bytes"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// WatchCommandFile polls a file and delivers each distinct content as a
// Command. It returns a stop function, safe to call more than once.
//
// This exists because Caido's child_process does not deliver writes to a
// child's stdin: the helper receives its `ready` message fine over stdout, and
// stdin EOF still shuts it down, but commands written by the plugin never
// arrive. A file the plugin rewrites is a channel that demonstrably works.
//
// Unchanged content is never re-delivered, so the helper does not restart its
// listener on every tick. A missing or unparseable file is ignored rather than
// fatal: the plugin may not have written one yet.
func WatchCommandFile(path string, interval time.Duration, fn func(Command)) func() {
	done := make(chan struct{})
	var once sync.Once

	go func() {
		var last []byte
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				body, err := os.ReadFile(path)
				if err != nil {
					continue // not written yet, or unreadable
				}
				if bytes.Equal(body, last) {
					continue
				}
				var c Command
				if err := json.Unmarshal(body, &c); err != nil {
					// Record it so a garbage file is not re-parsed every tick,
					// but deliver nothing.
					last = append(body[:0:0], body...)
					continue
				}
				last = append(body[:0:0], body...)
				fn(c)
			}
		}
	}()

	return func() { once.Do(func() { close(done) }) }
}

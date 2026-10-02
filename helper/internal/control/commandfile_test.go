package control

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWatchCommandFileDeliversEachChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "command.json")

	var mu sync.Mutex
	var got []Command
	stop := WatchCommandFile(path, 20*time.Millisecond, func(c Command) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, c)
	})
	defer stop()

	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	write(`{"type":"capture","enabled":true,"listen":"127.0.0.1:8886","forwardTo":"127.0.0.1:8080"}`)
	waitFor(t, &mu, &got, 1)
	write(`{"type":"capture","enabled":false}`)
	waitFor(t, &mu, &got, 2)

	mu.Lock()
	defer mu.Unlock()
	if !got[0].Enabled || got[0].Listen != "127.0.0.1:8886" {
		t.Errorf("first command = %+v", got[0])
	}
	if got[1].Enabled {
		t.Errorf("second command = %+v", got[1])
	}
}

// Polling must not re-deliver unchanged content, or the helper would restart
// its listener on every tick.
func TestWatchCommandFileIgnoresUnchangedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "command.json")
	if err := os.WriteFile(path, []byte(`{"type":"capture","enabled":true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var mu sync.Mutex
	var got []Command
	stop := WatchCommandFile(path, 10*time.Millisecond, func(c Command) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, c)
	})
	defer stop()

	waitFor(t, &mu, &got, 1)
	time.Sleep(120 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Errorf("delivered %d times, want exactly 1", len(got))
	}
}

func TestWatchCommandFileToleratesAMissingOrBadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "command.json")

	var mu sync.Mutex
	var got []Command
	stop := WatchCommandFile(path, 10*time.Millisecond, func(c Command) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, c)
	})
	defer stop()

	// Absent, then garbage: neither may deliver or panic.
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(got) != 0 {
		t.Errorf("delivered %d commands for absent/garbage input", len(got))
	}
	mu.Unlock()

	// A valid write afterwards must still be picked up.
	if err := os.WriteFile(path, []byte(`{"type":"capture","enabled":true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, &mu, &got, 1)
}

func TestWatchCommandFileStopsCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "command.json")
	stop := WatchCommandFile(path, 10*time.Millisecond, func(Command) {})
	stop()
	stop() // must be idempotent
}

func waitFor(t *testing.T, mu *sync.Mutex, got *[]Command, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		have := len(*got)
		mu.Unlock()
		if have >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d command(s)", n)
}

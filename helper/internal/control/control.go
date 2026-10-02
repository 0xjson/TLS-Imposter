// Package control is the JSON-lines protocol spoken over the helper's stdio.
// It is pure serialization: it does not know what any message means.
package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type Ready struct {
	Type           string   `json:"type"`
	Port           int      `json:"port"`
	Token          string   `json:"token"`
	Profiles       []string `json:"profiles"`
	DefaultProfile string   `json:"defaultProfile"`
	Version        string   `json:"version"`
}

type CaptureStatus struct {
	Type   string `json:"type"`
	State  string `json:"state"` // listening | stopped | error
	Listen string `json:"listen,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Captured struct {
	Type        string `json:"type"`
	ClientHello string `json:"clientHello"`
	JA3         string `json:"ja3"`
	JA3Text     string `json:"ja3Text"`
	JA4         string `json:"ja4"`
	CapturedAt  string `json:"capturedAt"`
}

type CaptureRejected struct {
	Type  string `json:"type"`
	Error string `json:"error"`
	JA4   string `json:"ja4,omitempty"`
}

type LogMsg struct {
	Type  string `json:"type"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

type Command struct {
	Type      string `json:"type"`
	Enabled   bool   `json:"enabled"`
	Listen    string `json:"listen"`
	ForwardTo string `json:"forwardTo"`
}

// Writer serializes messages to a stream, one JSON object per line.
// Emit is safe for concurrent use; lines never interleave.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (w *Writer) Emit(v any) error {
	// json.Marshal escapes any newline inside a string, so one message is
	// always exactly one line.
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.w.Write(b)
	return err
}

// Logf emits a diagnostic. Callers must never pass the auth token.
func (w *Writer) Logf(level, format string, args ...any) {
	_ = w.Emit(LogMsg{Type: "log", Level: level, Msg: fmt.Sprintf(format, args...)})
}

// ReadCommands consumes commands until EOF, which is the shutdown signal.
// Unparseable lines are skipped rather than fatal, so a protocol slip on one
// line cannot take the helper down.
func ReadCommands(r io.Reader, fn func(Command)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var c Command
		if err := json.Unmarshal(line, &c); err != nil {
			continue
		}
		fn(c)
	}
	return sc.Err()
}

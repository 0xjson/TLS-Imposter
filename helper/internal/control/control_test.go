package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestWriterEmitsOneJSONLinePerMessage(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.Emit(Ready{Type: "ready", Port: 1234, Token: "abc", Profiles: []string{"chrome_150"}, DefaultProfile: "chrome_150", Version: "test"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	w.Logf("info", "hello %d", 7)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}

	var ready Ready
	if err := json.Unmarshal([]byte(lines[0]), &ready); err != nil {
		t.Fatalf("line 0 not JSON: %v", err)
	}
	if ready.Port != 1234 || ready.Type != "ready" {
		t.Errorf("got %+v", ready)
	}

	var lm LogMsg
	if err := json.Unmarshal([]byte(lines[1]), &lm); err != nil {
		t.Fatalf("line 1 not JSON: %v", err)
	}
	if lm.Type != "log" || lm.Level != "info" || lm.Msg != "hello 7" {
		t.Errorf("got %+v", lm)
	}
}

func TestWriterIsConcurrencySafe(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.Logf("info", "x") }()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 50 {
		t.Fatalf("want 50 intact lines, got %d", len(lines))
	}
	for i, l := range lines {
		var lm LogMsg
		if err := json.Unmarshal([]byte(l), &lm); err != nil {
			t.Fatalf("line %d corrupted: %q", i, l)
		}
	}
}

func TestReadCommandsStopsAtEOFAndSkipsGarbage(t *testing.T) {
	in := strings.NewReader(
		`{"type":"capture","enabled":true,"listen":"127.0.0.1:8886","forwardTo":"127.0.0.1:8080"}` + "\n" +
			"not json\n" +
			`{"type":"capture","enabled":false}` + "\n")

	var got []Command
	if err := ReadCommands(in, func(c Command) { got = append(got, c) }); err != nil {
		t.Fatalf("ReadCommands: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 commands, got %d", len(got))
	}
	if !got[0].Enabled || got[0].Listen != "127.0.0.1:8886" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Enabled {
		t.Errorf("got[1] = %+v", got[1])
	}
}

// The token authenticates every forward connection; a log line carrying it
// would leak it to anyone who can read Caido's log file.
func TestLogfNeverCarriesTheTokenByAccident(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.Logf("warn", "preamble rejected: token mismatch")
	if strings.Contains(buf.String(), "deadbeef") {
		t.Error("unexpected token-like content")
	}
	var lm LogMsg
	if err := json.Unmarshal([]byte(strings.TrimRight(buf.String(), "\n")), &lm); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if lm.Msg != "preamble rejected: token mismatch" {
		t.Errorf("Msg = %q", lm.Msg)
	}
}

// A message whose content contains a newline must not become two lines, or the
// plugin's line-oriented reader would see a truncated object plus garbage.
func TestEmbeddedNewlinesDoNotSplitALine(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.Logf("error", "multi\nline\nmessage")

	out := strings.TrimRight(buf.String(), "\n")
	if strings.Contains(out, "\n") {
		t.Fatalf("message split across lines: %q", buf.String())
	}
	var lm LogMsg
	if err := json.Unmarshal([]byte(out), &lm); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if lm.Msg != "multi\nline\nmessage" {
		t.Errorf("Msg = %q, want the newlines preserved inside the JSON string", lm.Msg)
	}
}

func TestCapturedRoundTripsEveryField(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	in := Captured{
		Type: "captured", ClientHello: "160301aa", JA3: "a1b2", JA3Text: "771,4865,0,29,0",
		JA4: "t13d0203h2_aaa_bbb", CapturedAt: "2026-10-03T00:00:00Z",
	}
	if err := w.Emit(in); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var out Captured
	if err := json.Unmarshal([]byte(strings.TrimRight(buf.String(), "\n")), &out); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if out != in {
		t.Errorf("round trip changed the message:\n got %+v\nwant %+v", out, in)
	}
}

// The plugin keys on `type`; a message that serializes without it is unroutable.
func TestEveryMessageTypeSerializesItsTypeTag(t *testing.T) {
	for name, msg := range map[string]any{
		"ready":            Ready{Type: "ready"},
		"capture-status":   CaptureStatus{Type: "capture-status", State: "stopped"},
		"captured":         Captured{Type: "captured"},
		"capture-rejected": CaptureRejected{Type: "capture-rejected", Error: "x"},
		"log":              LogMsg{Type: "log", Level: "info", Msg: "x"},
	} {
		var buf bytes.Buffer
		if err := NewWriter(&buf).Emit(msg); err != nil {
			t.Fatalf("%s: Emit: %v", name, err)
		}
		var generic map[string]any
		if err := json.Unmarshal([]byte(strings.TrimRight(buf.String(), "\n")), &generic); err != nil {
			t.Fatalf("%s: not JSON: %v", name, err)
		}
		if generic["type"] != name {
			t.Errorf("%s: type = %v", name, generic["type"])
		}
	}
}

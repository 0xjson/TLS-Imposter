package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type helper struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	ready  map[string]any
}

// startHelper builds and runs the helper for the host platform.
func startHelper(t *testing.T) *helper {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "helper")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	cmd := exec.Command(bin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	h := &helper{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdoutPipe)}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	h.ready = h.expect(t, "ready", 20*time.Second)
	return h
}

// expect reads control messages until one of the wanted type arrives.
func (h *helper) expect(t *testing.T, want string, timeout time.Duration) map[string]any {
	t.Helper()
	type result struct {
		m   map[string]any
		err error
	}
	ch := make(chan result, 1)
	go func() {
		for {
			line, err := h.stdout.ReadString('\n')
			if err != nil {
				ch <- result{err: err}
				return
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				continue
			}
			if m["type"] == want {
				ch <- result{m: m}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("waiting for %q: %v", want, r.err)
		}
		return r.m
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for a %q message", want)
		return nil
	}
}

func (h *helper) send(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal command: %v", err)
	}
	if _, err := h.stdin.Write(append(b, '\n')); err != nil {
		t.Fatalf("write command: %v", err)
	}
}

func TestReadyAnnouncesPortTokenAndProfiles(t *testing.T) {
	h := startHelper(t)

	port, ok := h.ready["port"].(float64)
	if !ok || port <= 0 {
		t.Fatalf("ready.port = %v", h.ready["port"])
	}
	token, ok := h.ready["token"].(string)
	if !ok || len(token) < 32 {
		t.Errorf("ready.token = %q, want at least 32 hex characters", token)
	}
	profiles, ok := h.ready["profiles"].([]any)
	if !ok || len(profiles) < 20 {
		t.Errorf("ready.profiles has %d entries", len(profiles))
	}
	if d, _ := h.ready["defaultProfile"].(string); d == "" {
		t.Error("ready.defaultProfile is empty")
	}

	// The forward listener must be reachable on loopback.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", int(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("forward listener not reachable on loopback: %v", err)
	}
	c.Close()
}

func TestForwardsARequestThroughTheHelper(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		fmt.Fprint(w, "forwarded")
	}))
	defer target.Close()

	h := startHelper(t)
	port := int(h.ready["port"].(float64))
	token := h.ready["token"].(string)

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))
	var tport int
	_, _ = fmt.Sscanf(portStr, "%d", &tport)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial helper: %v", err)
	}
	defer conn.Close()

	pre := map[string]any{
		"token":       token,
		"target":      map[string]any{"host": host, "port": tport, "tls": true},
		"sni":         nil,
		"profile":     h.ready["defaultProfile"],
		"clientHello": nil,
		"timeoutSec":  30,
	}
	b, _ := json.Marshal(pre)
	fmt.Fprintf(conn, "AWESOMETLS/1 %s\n", b)
	_, _ = io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: decoy.invalid\r\n\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != 200 || string(body) != "forwarded" {
		t.Errorf("status=%d body=%q", res.StatusCode, body)
	}
	if got := res.Header.Get("X-Seen-Host"); got != "decoy.invalid" {
		t.Errorf("target saw Host %q, want the original passed through", got)
	}
}

// Without the token the connection must be dropped, so the helper cannot be
// used as an open proxy by anything else on the machine.
func TestRejectsAnUnauthenticatedConnection(t *testing.T) {
	h := startHelper(t)
	port := int(h.ready["port"].(float64))

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial helper: %v", err)
	}
	defer conn.Close()

	pre := map[string]any{
		"token":       "wrong-token",
		"target":      map[string]any{"host": "example.com", "port": 443, "tls": true},
		"profile":     h.ready["defaultProfile"],
		"clientHello": nil,
		"timeoutSec":  30,
	}
	b, _ := json.Marshal(pre)
	fmt.Fprintf(conn, "AWESOMETLS/1 %s\n", b)
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("want the connection closed with no reply when the token is wrong")
	}
}

func TestCaptureCommandStartsAndStopsTheListener(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	h := startHelper(t)

	h.send(t, map[string]any{
		"type": "capture", "enabled": true,
		"listen": "127.0.0.1:0", "forwardTo": backend.Addr().String(),
	})
	st := h.expect(t, "capture-status", 10*time.Second)
	if st["state"] != "listening" {
		t.Fatalf("capture state = %v, want listening (error: %v)", st["state"], st["error"])
	}
	listen, _ := st["listen"].(string)
	if listen == "" {
		t.Fatal("capture-status.listen is empty; the chosen port must be reported")
	}

	conn, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("dial capture listener: %v", err)
	}
	defer conn.Close()

	hello := buildTestHello(600)
	_, _ = conn.Write(append([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), hello...))

	cap := h.expect(t, "captured", 10*time.Second)
	if s, _ := cap["clientHello"].(string); len(s) != len(hello)*2 {
		t.Errorf("captured hello hex length = %d, want %d", len(s), len(hello)*2)
	}
	if s, _ := cap["ja4"].(string); !strings.Contains(s, "_") {
		t.Errorf("captured.ja4 = %q, want a JA4 string", s)
	}
	if s, _ := cap["ja3"].(string); len(s) != 32 {
		t.Errorf("captured.ja3 = %q, want a 32-character digest", s)
	}

	h.send(t, map[string]any{"type": "capture", "enabled": false})
	if st := h.expect(t, "capture-status", 10*time.Second); st["state"] != "stopped" {
		t.Errorf("capture state = %v, want stopped", st["state"])
	}
}

func TestExitsWhenStdinCloses(t *testing.T) {
	h := startHelper(t)

	if err := h.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not exit when stdin closed; it would outlive the plugin")
	}
}

// The token authenticates every connection, so it must not appear in any log
// message the plugin forwards to Caido's log file.
func TestTokenNeverAppearsInLogMessages(t *testing.T) {
	h := startHelper(t)
	token := h.ready["token"].(string)
	port := int(h.ready["port"].(float64))

	// Provoke log output with a rejected connection.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		line, err := h.stdout.ReadString('\n')
		if err != nil {
			break
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		if m["type"] != "log" {
			continue
		}
		if msg, _ := m["msg"].(string); strings.Contains(msg, token) {
			t.Fatalf("a log message contained the auth token: %q", msg)
		}
		break
	}
}

// buildTestHello produces a minimal ClientHello the fingerprint parser accepts:
// version, random, no session, two ciphers, null compression, and SNI.
func buildTestHello(pad int) []byte {
	var exts bytes.Buffer
	name := "example.com"
	sni := []byte{0x00}
	sni = append(sni, byte(len(name)>>8), byte(len(name)))
	sni = append(sni, name...)
	exts.Write([]byte{0x00, 0x00, byte((len(sni) + 2) >> 8), byte(len(sni) + 2),
		byte(len(sni) >> 8), byte(len(sni))})
	exts.Write(sni)
	// Padding extension to reach a realistic size.
	if pad > exts.Len()+8 {
		n := pad - exts.Len() - 8
		exts.Write([]byte{0x00, 0x15, byte(n >> 8), byte(n)})
		exts.Write(make([]byte, n))
	}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x04, 0x13, 0x01, 0x13, 0x02})
	body.Write([]byte{0x01, 0x00})
	body.Write([]byte{byte(exts.Len() >> 8), byte(exts.Len())})
	body.Write(exts.Bytes())

	hs := []byte{0x01, byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())}
	hs = append(hs, body.Bytes()...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

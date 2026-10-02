package forward

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/httpwire"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

const testToken = "testtoken0123456789"

// dialHandled runs Handle against one end of a pipe and returns the other end.
func dialHandled(t *testing.T, relay RelayFunc) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	cache := NewCache(time.Minute)
	t.Cleanup(func() { cache.Close(); client.Close() })
	go Handle(server, testToken, cache, relay, func(string, ...any) {})
	return client
}

func writePreamble(t *testing.T, w io.Writer, cfg *preamble.Config) {
	t.Helper()
	cfg.Token = testToken
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal preamble: %v", err)
	}
	if _, err := fmt.Fprintf(w, "%s%s\n", preamble.Magic, b); err != nil {
		t.Fatalf("write preamble: %v", err)
	}
}

func targetConfig(t *testing.T, h http.Handler) *preamble.Config {
	t.Helper()
	_, cfg := tlsServer(t, h)
	return cfg
}

// newRawTLSServer serves a self-signed TLS listener whose connections are
// handled by fn, for responses net/http cannot produce.
func newRawTLSServer(t *testing.T, fn func(net.Conn)) net.Listener {
	t.Helper()
	probe := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cfg := probe.TLS.Clone()
	probe.Close()
	cfg.NextProtos = []string{"http/1.1"}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fn(c)
		}
	}()
	return ln
}

func TestHandleServesTwoRequestsOnOneConnection(t *testing.T) {
	var hits int
	cfg := targetConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprintf(w, "hit%d", hits)
	}))

	conn := dialHandled(t, nil)
	writePreamble(t, conn, cfg)

	br := bufio.NewReader(conn)
	for i := 1; i <= 2; i++ {
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"); err != nil {
			t.Fatalf("write request %d: %v", i, err)
		}
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if got, want := string(body), fmt.Sprintf("hit%d", i); got != want {
			t.Errorf("response %d body = %q, want %q", i, got, want)
		}
	}
	if hits != 2 {
		t.Errorf("target saw %d requests, want 2 — the connection was not reused", hits)
	}
}

// Review Focus 4: after an error the stream must be correctly framed, not left
// half-written.
func TestHandleKeepsConnectionUsableAfterAnErrorResponse(t *testing.T) {
	bad := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: refusedPort(t), TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 5,
	}

	conn := dialHandled(t, nil)
	writePreamble(t, conn, bad)

	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()

	// A refused connection is a 502; a silent drop would be a 504. Either is a
	// correct classification, and the property under test is the framing.
	if res.StatusCode != 502 && res.StatusCode != 504 {
		t.Errorf("StatusCode = %d, want 502 or 504", res.StatusCode)
	}
	if res.Header.Get("X-Awesome-Tls-Error") == "" {
		t.Error("want X-Awesome-Tls-Error on the error response")
	}
	if !strings.Contains(string(body), "Awesome TLS") {
		t.Errorf("body = %q, want the helper's error text", body)
	}
	// ReadResponse succeeding and the body terminating proves the client is not
	// left waiting for more bytes.
}

func TestHandleRejectsABadToken(t *testing.T) {
	conn := dialHandled(t, nil)
	cfg := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 443, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
		Token:      "wrong-token",
	}
	b, _ := json.Marshal(cfg)
	fmt.Fprintf(conn, "%s%s\n", preamble.Magic, b)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("want the connection closed with no reply when the token is wrong")
	}
}

func TestHandleRejectsAMissingPreamble(t *testing.T) {
	conn := dialHandled(t, nil)
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("want the connection closed when no preamble is sent")
	}
}

func TestHandleReturns504OnTimeout(t *testing.T) {
	cfg := targetConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	cfg.TimeoutSec = 1

	conn := dialHandled(t, nil)
	writePreamble(t, conn, cfg)
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 504 {
		t.Errorf("StatusCode = %d, want 504", res.StatusCode)
	}
}

func TestHandleHandsUpgradeRequestsToTheRelay(t *testing.T) {
	var relayed *httpwire.Request
	done := make(chan struct{})
	relay := func(conn net.Conn, cfg *preamble.Config, req *httpwire.Request) error {
		relayed = req
		close(done)
		return nil
	}

	conn := dialHandled(t, relay)
	writePreamble(t, conn, &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 443, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
	})
	_, _ = io.WriteString(conn,
		"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay was not invoked for an Upgrade request")
	}
	if relayed.Target != "/ws" {
		t.Errorf("relay received target %q", relayed.Target)
	}
}

func TestHandleAnswers501WhenNoRelayIsConfigured(t *testing.T) {
	conn := dialHandled(t, nil)
	writePreamble(t, conn, &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 443, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
	})
	_, _ = io.WriteString(conn,
		"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 501 {
		t.Errorf("StatusCode = %d, want 501", res.StatusCode)
	}
}

// Review Focus 2: a response framed only by connection close must terminate and
// still get an exact Content-Length.
func TestHandleReadsResponseFramedOnlyByConnectionClose(t *testing.T) {
	ln := newRawTLSServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c,
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclosed-framed")
		c.Close()
	})

	host, port := hostPort(t, ln.Addr().String())

	conn := dialHandled(t, nil)
	writePreamble(t, conn, &preamble.Config{
		Target:     preamble.Target{Host: host, Port: port, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 10,
	})
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if string(body) != "closed-framed" {
		t.Errorf("body = %q, want %q", body, "closed-framed")
	}
	if res.ContentLength != int64(len("closed-framed")) {
		t.Errorf("ContentLength = %d, want %d — an exact length must be computed",
			res.ContentLength, len("closed-framed"))
	}
}

// A HEAD response must not gain a body, or the client desyncs.
func TestHandleWritesNoBodyForHEAD(t *testing.T) {
	cfg := targetConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1234")
		w.WriteHeader(200)
	}))

	conn := dialHandled(t, nil)
	writePreamble(t, conn, cfg)
	_, _ = io.WriteString(conn, "HEAD / HTTP/1.1\r\nHost: h\r\n\r\n")

	br := bufio.NewReader(conn)
	// Parse manually: http.ReadResponse needs the request to know about HEAD.
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("status = %q", status)
	}
	var sawBlank bool
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if strings.TrimRight(line, "\r\n") == "" {
			sawBlank = true
			break
		}
	}
	if !sawBlank {
		t.Fatal("headers were not terminated")
	}
	// Nothing further should arrive for a HEAD.
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _ := br.Read(make([]byte, 16)); n > 0 {
		t.Errorf("%d body bytes written for a HEAD response", n)
	}
}

// refusedPort returns a loopback port with nothing listening, by binding one
// and releasing it. Connecting there yields ECONNREFUSED immediately, unlike a
// low port such as 1, which this environment silently drops until the timeout.
func refusedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port := hostPort(t, ln.Addr().String())
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

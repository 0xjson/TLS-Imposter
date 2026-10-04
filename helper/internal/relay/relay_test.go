package relay

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xjson/tls-imposter/helper/internal/httpwire"
	"github.com/0xjson/tls-imposter/helper/internal/preamble"
)

// echoUpgradeServer accepts a raw TLS connection, replies 101, then echoes.
// It reports the ALPN protocol each client negotiated.
func echoUpgradeServer(t *testing.T) (*preamble.Config, func() []string) {
	t.Helper()

	probe := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsCfg := probe.TLS.Clone()
	probe.Close()
	// Offer both so the test can tell which one the client asked for.
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	negotiated := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				if err := tc.Handshake(); err != nil {
					return
				}
				negotiated <- tc.ConnectionState().NegotiatedProtocol

				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "" {
						break
					}
				}
				_, _ = io.WriteString(c,
					"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				_, _ = io.Copy(c, br) // echo everything after the handshake
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	drain := func() []string {
		var out []string
		for {
			select {
			case p := <-negotiated:
				out = append(out, p)
			case <-time.After(300 * time.Millisecond):
				return out
			}
		}
	}

	return &preamble.Config{
		Target:     preamble.Target{Host: host, Port: port, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
	}, drain
}

func upgradeRequest(t *testing.T) *httpwire.Request {
	t.Helper()
	raw := "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	return req
}

func TestRelayCompletesTheUpgradeAndPipesBothDirections(t *testing.T) {
	cfg, drain := echoUpgradeServer(t)
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		if err := Relay(server, cfg, upgradeRequest(t)); err != nil {
			t.Logf("Relay returned: %v", err)
		}
	}()

	br := bufio.NewReader(client)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("StatusCode = %d, want 101", res.StatusCode)
	}

	// Post-handshake bytes must survive untouched in both directions.
	payload := []byte{0x81, 0x03, 'a', 'b', 'c'}
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got := make([]byte, len(payload))
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo = % x, want % x", got, payload)
	}

	if protos := drain(); len(protos) == 0 || protos[0] != "http/1.1" {
		t.Errorf("negotiated ALPN = %v, want http/1.1 — browsers do not use h2 for WebSockets", protos)
	}
}

// 27 of the bundled profiles cannot expose a spec (Task 6); the relay must
// still force http/1.1 for them, via uTLS's own flag on the named ID.
func TestRelayForcesHTTP11ForANamedOnlyProfile(t *testing.T) {
	cfg, drain := echoUpgradeServer(t)
	cfg.Profile = "chrome_103" // named-ID only
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		if err := Relay(server, cfg, upgradeRequest(t)); err != nil {
			t.Logf("Relay returned: %v", err)
		}
	}()

	res, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if res.StatusCode != 101 {
		t.Errorf("StatusCode = %d, want 101", res.StatusCode)
	}
	if protos := drain(); len(protos) == 0 || protos[0] != "http/1.1" {
		t.Errorf("negotiated ALPN = %v, want http/1.1 for a named-only profile", protos)
	}
}

func TestRelayUsesACapturedClientHello(t *testing.T) {
	cfg, drain := echoUpgradeServer(t)
	cfg.ClientHello = helloHex(t)
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		if err := Relay(server, cfg, upgradeRequest(t)); err != nil {
			t.Logf("Relay returned: %v", err)
		}
	}()

	res, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if res.StatusCode != 101 {
		t.Errorf("StatusCode = %d, want 101", res.StatusCode)
	}
	// Even a captured h2-offering hello must be forced to http/1.1.
	if protos := drain(); len(protos) == 0 || protos[0] != "http/1.1" {
		t.Errorf("negotiated ALPN = %v, want http/1.1 with a captured hello", protos)
	}
}

// The original request bytes must be replayed verbatim: a rewritten
// Sec-WebSocket-Key would break the handshake.
func TestRelayReplaysTheRequestBytesVerbatim(t *testing.T) {
	received := make(chan string, 1)
	probe := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsCfg := probe.TLS.Clone()
	probe.Close()
	tlsCfg.NextProtos = []string{"http/1.1"}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		received <- string(buf[:n])
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	client, server := net.Pipe()
	defer client.Close()
	req := upgradeRequest(t)
	go func() {
		_ = Relay(server, &preamble.Config{
			Target:     preamble.Target{Host: host, Port: port, TLS: true},
			Profile:    "chrome_150",
			TimeoutSec: 10,
		}, req)
	}()

	select {
	case got := <-received:
		if got != string(req.Head) {
			t.Errorf("target received:\n%q\nwant the original bytes:\n%q", got, req.Head)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never received the request")
	}
}

func TestRelayFailsWhenTheTargetIsUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	ln.Close() // nothing listening now

	cfg := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: port, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 3,
	}
	client, server := net.Pipe()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- Relay(server, cfg, upgradeRequest(t)) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("want an error when the target refuses the connection")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Relay did not return")
	}
}

func TestRelayRejectsAnUnknownProfile(t *testing.T) {
	cfg := &preamble.Config{
		Target:     preamble.Target{Host: "127.0.0.1", Port: 443, TLS: true},
		Profile:    "netscape_4",
		TimeoutSec: 3,
	}
	client, server := net.Pipe()
	defer client.Close()
	if err := Relay(server, cfg, upgradeRequest(t)); err == nil {
		t.Error("want an error for an unknown profile")
	}
}

package forward

import (
	"bufio"
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

// tlsServer starts an HTTPS test server and returns a config pointing at it.
func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, *preamble.Config) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	host, port := hostPort(t, strings.TrimPrefix(srv.URL, "https://"))
	return srv, &preamble.Config{
		Target:     preamble.Target{Host: host, Port: port, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 30,
	}
}

func hostPort(t *testing.T, authority string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", authority, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

func parseReq(t *testing.T, raw string) *httpwire.Request {
	t.Helper()
	req, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	return req
}

func send(t *testing.T, cfg *preamble.Config, req *httpwire.Request) *Result {
	t.Helper()
	c := NewCache(time.Minute)
	t.Cleanup(c.Close)
	client, err := c.Get(cfg)
	if err != nil {
		t.Fatalf("cache.Get: %v", err)
	}
	res, err := Send(client, cfg, req)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	return res
}

// Review Focus 1: the Host header must never decide where we dial.
func TestSendDialsThePreambleTargetNotTheHostHeader(t *testing.T) {
	var gotHost, gotPath string
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.RequestURI()
		w.Write([]byte("ok"))
	}))

	req := parseReq(t, "GET /p?q=1 HTTP/1.1\r\nHost: decoy.invalid\r\n\r\n")
	res := send(t, cfg, req)

	if res.Code != 200 {
		t.Fatalf("Code = %d, want 200 (the request did not reach the target)", res.Code)
	}
	if gotHost != "decoy.invalid" {
		t.Errorf("server saw Host %q, want the original %q passed through", gotHost, "decoy.invalid")
	}
	if gotPath != "/p?q=1" {
		t.Errorf("server saw path %q, want /p?q=1", gotPath)
	}
}

func TestSendPreservesHeaderOrder(t *testing.T) {
	var arrived []string
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, k := range []string{"X-One", "X-Two", "X-Three"} {
			if r.Header.Get(k) != "" {
				arrived = append(arrived, k)
			}
		}
		w.Write([]byte("ok"))
	}))

	req := parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\nX-Three: 3\r\nX-One: 1\r\nX-Two: 2\r\n\r\n")
	if got := req.OrderedNames(); got[1] != "x-three" {
		t.Fatalf("parser lost order before sending: %v", got)
	}
	if res := send(t, cfg, req); res.Code != 200 {
		t.Fatalf("Code = %d", res.Code)
	}
	if len(arrived) != 3 {
		t.Errorf("not all headers arrived: %v", arrived)
	}
}

func TestSendDoesNotDecompressTheBody(t *testing.T) {
	// gzip("hello"). The helper must hand the bytes back untouched so
	// Content-Encoding still describes them.
	gz := []byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
	}
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(gz)
	}))

	req := parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n")
	res := send(t, cfg, req)

	if string(res.Body) == "hello" {
		t.Fatal("body was decompressed; Content-Encoding would then be a lie")
	}
	if len(res.Body) != len(gz) {
		t.Errorf("Body length = %d, want the %d compressed bytes", len(res.Body), len(gz))
	}
	var sawEncoding bool
	for _, h := range res.Headers {
		if strings.EqualFold(h.Name, "Content-Encoding") && h.Value == "gzip" {
			sawEncoding = true
		}
	}
	if !sawEncoding {
		t.Error("Content-Encoding: gzip missing from the returned headers")
	}
}

func TestSendCarriesRequestBody(t *testing.T) {
	var got string
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(201)
	}))

	req := parseReq(t, "POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello world")
	res := send(t, cfg, req)

	if res.Code != 201 {
		t.Errorf("Code = %d, want 201", res.Code)
	}
	if got != "hello world" {
		t.Errorf("server received body %q", got)
	}
}

func TestSendReturnsDuplicateResponseHeaders(t *testing.T) {
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Write([]byte("ok"))
	}))

	res := send(t, cfg, parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	var n int
	for _, h := range res.Headers {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("got %d Set-Cookie headers, want 2", n)
	}
}

// Connection-specific headers are illegal in HTTP/2 and meaningless after
// re-framing, so they must not be forwarded.
func TestSendDropsHopByHopHeaders(t *testing.T) {
	var seen []string
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, k := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Upgrade"} {
			if r.Header.Get(k) != "" {
				seen = append(seen, k)
			}
		}
		w.Write([]byte("ok"))
	}))

	req := parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\n"+
		"Keep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\n\r\n")
	if res := send(t, cfg, req); res.Code != 200 {
		t.Fatalf("Code = %d", res.Code)
	}
	if len(seen) != 0 {
		t.Errorf("hop-by-hop headers reached the target: %v", seen)
	}
}

func TestSendReportsTheStatusReason(t *testing.T) {
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	res := send(t, cfg, parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	if res.Code != 404 {
		t.Errorf("Code = %d", res.Code)
	}
	if res.Reason != "Not Found" {
		t.Errorf("Reason = %q, want %q", res.Reason, "Not Found")
	}
}

func TestSendSurfacesDialFailures(t *testing.T) {
	cfg := &preamble.Config{
		// Port 1 on loopback refuses connections.
		Target:     preamble.Target{Host: "127.0.0.1", Port: 1, TLS: true},
		Profile:    "chrome_150",
		TimeoutSec: 5,
	}
	c := NewCache(time.Minute)
	defer c.Close()
	client, err := c.Get(cfg)
	if err != nil {
		t.Fatalf("cache.Get: %v", err)
	}
	if _, err := Send(client, cfg, parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")); err == nil {
		t.Error("want an error when the target refuses the connection")
	}
}

// A captured hello must produce a working connection, not just a valid spec.
func TestSendWorksWithACapturedClientHello(t *testing.T) {
	_, cfg := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("captured-ok"))
	}))
	cfg.ClientHello = helloHex(t)

	res := send(t, cfg, parseReq(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	if res.Code != 200 || string(res.Body) != "captured-ok" {
		t.Errorf("Code = %d body = %q", res.Code, res.Body)
	}
}

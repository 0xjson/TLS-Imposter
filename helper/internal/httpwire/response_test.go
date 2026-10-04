package httpwire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWriteResponseSetsExactContentLengthAndDropsTransferEncoding(t *testing.T) {
	var buf bytes.Buffer
	in := []Header{
		{"Content-Type", "text/html"},
		{"Transfer-Encoding", "chunked"},
		{"Content-Length", "999"},
		{"Set-Cookie", "a=1"},
		{"Set-Cookie", "b=2"},
	}
	if err := WriteResponse(&buf, 200, "OK", in, []byte("hello"), true); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	out := buf.String()

	if !strings.HasPrefix(out, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("status line = %q", out[:min(32, len(out))])
	}
	if !strings.Contains(out, "Content-Length: 5\r\n") {
		t.Errorf("want recomputed Content-Length: 5, got:\n%s", out)
	}
	if strings.Count(out, "Content-Length") != 1 {
		t.Errorf("Content-Length must appear exactly once, got:\n%s", out)
	}
	if strings.Contains(out, "Transfer-Encoding") {
		t.Errorf("Transfer-Encoding must be dropped, got:\n%s", out)
	}
	if strings.Count(out, "Set-Cookie") != 2 {
		t.Errorf("both Set-Cookie headers must survive, got:\n%s", out)
	}
	if !strings.HasSuffix(out, "\r\n\r\nhello") {
		t.Errorf("body must follow a blank line, got:\n%s", out)
	}
}

func TestBodilessResponsesGetNoBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		code   int
	}{
		{"HEAD", "HEAD", 200},
		{"204", "GET", 204},
		{"304", "GET", 304},
		{"1xx", "GET", 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if BodyAllowed(tc.method, tc.code) {
				t.Fatalf("BodyAllowed(%q, %d) = true, want false", tc.method, tc.code)
			}
			var buf bytes.Buffer
			err := WriteResponse(&buf, tc.code, "x", []Header{{"Content-Type", "text/html"}},
				[]byte("SHOULD NOT APPEAR"), false)
			if err != nil {
				t.Fatalf("WriteResponse: %v", err)
			}
			out := buf.String()
			if strings.Contains(out, "SHOULD NOT APPEAR") {
				t.Errorf("body written for a bodiless response:\n%s", out)
			}
			if !strings.HasSuffix(out, "\r\n\r\n") {
				t.Errorf("headers must still be terminated by a blank line:\n%q", out)
			}
		})
	}
}

func TestHeadKeepsUpstreamContentLength(t *testing.T) {
	// A HEAD response advertises the length the body would have had; the helper
	// must not rewrite it to 0, which would misreport the resource size.
	var buf bytes.Buffer
	if err := WriteResponse(&buf, 200, "OK",
		[]Header{{"Content-Length", "4096"}}, nil, false); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	if !strings.Contains(buf.String(), "Content-Length: 4096\r\n") {
		t.Errorf("want upstream Content-Length preserved, got:\n%s", buf.String())
	}
}

func TestBodyAllowedForOrdinaryResponses(t *testing.T) {
	if !BodyAllowed("GET", 200) || !BodyAllowed("POST", 404) || !BodyAllowed("GET", 500) {
		t.Error("ordinary responses must allow a body")
	}
	// Method comparison is case-insensitive on the wire.
	if BodyAllowed("head", 200) {
		t.Error("BodyAllowed must treat lowercase head as HEAD")
	}
}

func TestWriteErrorCarriesDiagnosticHeaderAndBody(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteError(&buf, 502, "Bad Gateway", errors.New("dial tcp: refused")); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "HTTP/1.1 502 Bad Gateway\r\n") {
		t.Errorf("status line = %q", out)
	}
	if !strings.Contains(out, "X-Tls-Imposter-Error: dial tcp: refused\r\n") {
		t.Errorf("want diagnostic header, got:\n%s", out)
	}
	if !strings.Contains(out, "dial tcp: refused") {
		t.Errorf("want reason in the body, got:\n%s", out)
	}
	if !strings.Contains(out, "Connection: close\r\n") {
		t.Errorf("want Connection: close so the stream ends cleanly, got:\n%s", out)
	}
}

func TestWriteErrorSanitizesHeaderValue(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteError(&buf, 502, "Bad Gateway", errors.New("line1\r\nInjected: yes")); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	if strings.Contains(buf.String(), "\r\nInjected: yes") {
		t.Errorf("CRLF in an error string must not forge a header:\n%q", buf.String())
	}
}

// An upstream header value carrying CRLF must not be able to inject headers
// into what we write back to Caido.
func TestUpstreamHeaderCannotInjectCRLF(t *testing.T) {
	var buf bytes.Buffer
	evil := []Header{{"X-Evil", "ok\r\nX-Injected: yes"}, {"X-Evil-Name\r\nX-Also: y", "v"}}
	if err := WriteResponse(&buf, 200, "OK", evil, []byte("b"), true); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	out := buf.String()
	// The property is that no injected text can START a header line. Surviving
	// as inert text inside one value is fine and unavoidable.
	if strings.Contains(out, "\r\nX-Injected") {
		t.Errorf("CRLF in a header value forged a header line:\n%q", out)
	}
	if strings.Contains(out, "\r\nX-Also") {
		t.Errorf("CRLF in a header name forged a header line:\n%q", out)
	}
	// Exactly: status line, 2 sanitized headers, Content-Length, blank, body.
	head := strings.SplitN(out, "\r\n\r\n", 2)[0]
	if got := len(strings.Split(head, "\r\n")); got != 4 {
		t.Errorf("want 4 head lines (status + 2 headers + Content-Length), got %d:\n%q", got, head)
	}
}

// A nil error must not panic, and an empty reason must still produce a valid
// status line.
func TestWriteErrorAndReasonDegradeSafely(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteError(&buf, 500, "", nil); err != nil {
		t.Fatalf("WriteError(nil): %v", err)
	}
	if !strings.HasPrefix(buf.String(), "HTTP/1.1 500 ") {
		t.Errorf("status line = %q", buf.String())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

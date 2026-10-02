package httpwire

import (
	"bufio"
	"strings"
	"testing"
)

func parse(t *testing.T, raw string) *Request {
	t.Helper()
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest(%q): %v", raw, err)
	}
	return req
}

func TestPreservesHeaderOrderCasingAndDuplicates(t *testing.T) {
	req := parse(t, "GET /x HTTP/1.1\r\n"+
		"Host: example.com\r\n"+
		"X-Weird-CASE: 1\r\n"+
		"Cookie: a=1\r\n"+
		"cookie: b=2\r\n"+
		"Accept: */*\r\n"+
		"\r\n")

	want := []Header{
		{"Host", "example.com"},
		{"X-Weird-CASE", "1"},
		{"Cookie", "a=1"},
		{"cookie", "b=2"},
		{"Accept", "*/*"},
	}
	if len(req.Headers) != len(want) {
		t.Fatalf("got %d headers, want %d: %+v", len(req.Headers), len(want), req.Headers)
	}
	for i := range want {
		if req.Headers[i] != want[i] {
			t.Errorf("header %d = %+v, want %+v", i, req.Headers[i], want[i])
		}
	}

	if got := req.Get("COOKIE"); got != "a=1" {
		t.Errorf("Get is case-insensitive and first-match: got %q", got)
	}
	if got := req.Get("absent"); got != "" {
		t.Errorf("Get(absent) = %q, want empty", got)
	}
}

func TestKeepsRequestTargetVerbatim(t *testing.T) {
	req := parse(t, "GET /a%2Fb//c?q=1%20%2B2&r=%2f HTTP/1.1\r\nHost: h\r\n\r\n")
	if req.Target != "/a%2Fb//c?q=1%20%2B2&r=%2f" {
		t.Errorf("Target = %q; must not be re-encoded or normalized", req.Target)
	}
	if req.Method != "GET" || req.Proto != "HTTP/1.1" {
		t.Errorf("Method/Proto = %q/%q", req.Method, req.Proto)
	}
}

func TestReducesAbsoluteFormTargetToOriginForm(t *testing.T) {
	req := parse(t, "GET http://example.com/p?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if req.Target != "/p?q=1" {
		t.Errorf("Target = %q, want /p?q=1", req.Target)
	}

	// https, and an authority with no path at all.
	bare := parse(t, "GET https://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if bare.Target != "/" {
		t.Errorf("Target = %q, want /", bare.Target)
	}
}

func TestReadsContentLengthBody(t *testing.T) {
	req := parse(t, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello")
	if string(req.Body) != "hello" {
		t.Errorf("Body = %q", req.Body)
	}
}

func TestZeroContentLengthYieldsEmptyBody(t *testing.T) {
	req := parse(t, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n")
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty", req.Body)
	}
}

func TestDecodesChunkedBody(t *testing.T) {
	req := parse(t, "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	if string(req.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", req.Body, "hello world")
	}
}

func TestNoBodyWhenNeitherFramingHeaderPresent(t *testing.T) {
	req := parse(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty", req.Body)
	}
}

// A body containing arbitrary bytes must survive: this is a security tool and
// payloads are routinely not valid UTF-8.
func TestBinaryBodySurvivesByteForByte(t *testing.T) {
	body := "\x00\x01\x85\xff\xfe binary \x7f"
	req := parse(t, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: "+
		itoa(len(body))+"\r\n\r\n"+body)
	if string(req.Body) != body {
		t.Errorf("Body = %q, want %q", req.Body, body)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestDetectsUpgradeOnlyWhenBothHeadersAgree(t *testing.T) {
	ws := parse(t, "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if !ws.IsUpgrade {
		t.Error("websocket upgrade not detected")
	}

	no := parse(t, "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n\r\n")
	if no.IsUpgrade {
		t.Error("false positive: Connection does not list upgrade")
	}

	multi := parse(t, "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n")
	if !multi.IsUpgrade {
		t.Error("upgrade in a comma-separated Connection list not detected")
	}

	// Upgrade header with no Connection header at all.
	lone := parse(t, "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n")
	if lone.IsUpgrade {
		t.Error("false positive: no Connection header")
	}
}

func TestHeadRetainsOriginalBytesForTheRelay(t *testing.T) {
	raw := "GET /s HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	req := parse(t, raw)
	if string(req.Head) != raw {
		t.Errorf("Head = %q, want the original bytes %q", req.Head, raw)
	}
}

func TestOrderedNamesAreLowercased(t *testing.T) {
	req := parse(t, "GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nx-b: 2\r\n\r\n")
	got := req.OrderedNames()
	want := []string{"host", "x-a", "x-b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("OrderedNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// An empty header value is legal and must not be dropped or crash the parser.
func TestEmptyHeaderValueIsKept(t *testing.T) {
	req := parse(t, "GET / HTTP/1.1\r\nHost: h\r\nX-Empty:\r\nX-Spaced:   \r\n\r\n")
	if got := len(req.Headers); got != 3 {
		t.Fatalf("got %d headers, want 3: %+v", got, req.Headers)
	}
	if req.Headers[1].Name != "X-Empty" || req.Headers[1].Value != "" {
		t.Errorf("headers[1] = %+v", req.Headers[1])
	}
	if req.Headers[2].Value != "" {
		t.Errorf("trailing spaces should trim to empty, got %q", req.Headers[2].Value)
	}
}

func TestRejectsOversizedAndMalformed(t *testing.T) {
	for name, in := range map[string]string{
		"malformed request line":  "GARBAGE\r\n\r\n",
		"empty input":             "",
		"two tokens only":         "GET /\r\n\r\n",
		"bad protocol":            "GET / SPDY/3\r\nHost: h\r\n\r\n",
		"header without colon":    "GET / HTTP/1.1\r\nHost example.com\r\n\r\n",
		"header starting colon":   "GET / HTTP/1.1\r\n: value\r\n\r\n",
		"bad content-length":      "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
		"negative content-length": "POST / HTTP/1.1\r\nContent-Length: -5\r\n\r\n",
		"truncated body":          "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort",
		"unterminated headers":    "GET / HTTP/1.1\r\nHost: h\r\n",
	} {
		if _, err := ReadRequest(bufio.NewReader(strings.NewReader(in))); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

// Content-Length beyond the cap must be refused rather than allocated.
func TestRejectsBodyOverTheCap(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 999999999999\r\n\r\n"
	_, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatal("want an error for an oversized Content-Length")
	}
}

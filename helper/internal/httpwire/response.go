package httpwire

import (
	"fmt"
	"io"
	"strings"
)

// BodyAllowed reports whether a response to method with this status code may
// carry a body. Writing one where it is forbidden desynchronizes the client.
func BodyAllowed(method string, code int) bool {
	if strings.EqualFold(method, "HEAD") {
		return false
	}
	switch {
	case code >= 100 && code < 200:
		return false
	case code == 204 || code == 304:
		return false
	}
	return true
}

// WriteResponse serializes a complete, buffered HTTP/1.1 response.
//
// When bodyAllowed is true, Content-Length is replaced with the exact length of
// body. When it is false, body is not written and any upstream Content-Length
// is preserved, because it describes the resource rather than this message.
// Transfer-Encoding is always dropped: the message is framed by Content-Length.
func WriteResponse(w io.Writer, code int, reason string, headers []Header, body []byte, bodyAllowed bool) error {
	var b strings.Builder

	if reason == "" {
		reason = "Status"
	}
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, sanitizeHeaderValue(reason))

	for _, h := range headers {
		switch {
		case strings.EqualFold(h.Name, "Transfer-Encoding"):
			continue
		case strings.EqualFold(h.Name, "Content-Length") && bodyAllowed:
			continue // replaced below
		}
		fmt.Fprintf(&b, "%s: %s\r\n", sanitizeHeaderName(h.Name), sanitizeHeaderValue(h.Value))
	}

	if bodyAllowed {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if bodyAllowed && len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// WriteError reports a helper-side failure in a form visible in Caido's history.
func WriteError(w io.Writer, code int, reason string, detail error) error {
	msg := "unknown error"
	if detail != nil {
		msg = detail.Error()
	}
	// Collapse line breaks once, for both the header and the body. A CRLF
	// cannot forge a header in a Content-Length-framed body, but a diagnostic
	// string has no use for one, and leaving it in invites doubt about whether
	// the framing is safe.
	msg = sanitizeHeaderValue(msg)
	body := []byte("Awesome TLS: " + msg + "\n")
	return WriteResponse(w, code, reason, []Header{
		{"Content-Type", "text/plain; charset=utf-8"},
		{"X-Awesome-Tls-Error", msg},
		{"Connection", "close"},
	}, body, true)
}

// sanitizeHeaderValue removes CR and LF so an upstream or error string cannot
// forge additional headers.
func sanitizeHeaderValue(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

func sanitizeHeaderName(n string) string {
	return strings.NewReplacer("\r", "", "\n", "", ":", "", " ", "").Replace(n)
}

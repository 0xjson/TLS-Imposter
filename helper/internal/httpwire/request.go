// Package httpwire reads and writes HTTP/1.1 on the wire while preserving the
// details net/http discards: header order, header casing, duplicate headers,
// and the request-target exactly as the client wrote it.
//
// It knows nothing about TLS.
package httpwire

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http/httputil"
	"strconv"
	"strings"
)

const MaxBodyBytes = 256 << 20

var ErrBodyTooLarge = errors.New("httpwire: body exceeds maximum size")

type Header struct {
	Name  string
	Value string
}

type Request struct {
	Method  string
	Target  string // request-target, verbatim
	Proto   string
	Headers []Header
	Body    []byte
	// IsUpgrade reports an Upgrade handshake: an Upgrade header plus "upgrade"
	// among the Connection tokens.
	IsUpgrade bool
	// Head is the original request-line-plus-headers bytes, which the relay
	// replays verbatim.
	Head []byte
}

func (r *Request) Get(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func (r *Request) OrderedNames() []string {
	names := make([]string, 0, len(r.Headers))
	for _, h := range r.Headers {
		names = append(names, strings.ToLower(h.Name))
	}
	return names
}

func ReadRequest(br *bufio.Reader) (*Request, error) {
	var head bytes.Buffer

	line, err := readLine(br, &head)
	if err != nil {
		return nil, fmt.Errorf("httpwire: read request line: %w", err)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("httpwire: malformed request line %q", line)
	}
	req := &Request{Method: parts[0], Target: parts[1], Proto: parts[2]}
	if !strings.HasPrefix(req.Proto, "HTTP/") {
		return nil, fmt.Errorf("httpwire: malformed protocol %q", req.Proto)
	}
	if req.Method == "" || req.Target == "" {
		return nil, fmt.Errorf("httpwire: malformed request line %q", line)
	}
	req.Target = originForm(req.Target)

	for {
		line, err := readLine(br, &head)
		if err != nil {
			return nil, fmt.Errorf("httpwire: read header: %w", err)
		}
		if line == "" {
			break
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return nil, fmt.Errorf("httpwire: malformed header %q", line)
		}
		req.Headers = append(req.Headers, Header{
			Name:  line[:i],
			Value: strings.Trim(line[i+1:], " \t"),
		})
	}
	req.Head = head.Bytes()

	req.IsUpgrade = req.Get("Upgrade") != "" && hasToken(req.Get("Connection"), "upgrade")

	if err := req.readBody(br); err != nil {
		return nil, err
	}
	return req, nil
}

func (r *Request) readBody(br *bufio.Reader) error {
	if hasToken(r.Get("Transfer-Encoding"), "chunked") {
		body, err := io.ReadAll(io.LimitReader(httputil.NewChunkedReader(br), MaxBodyBytes+1))
		if err != nil {
			return fmt.Errorf("httpwire: read chunked body: %w", err)
		}
		if len(body) > MaxBodyBytes {
			return ErrBodyTooLarge
		}
		r.Body = body
		return nil
	}

	cl := r.Get("Content-Length")
	if cl == "" {
		return nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("httpwire: bad Content-Length %q", cl)
	}
	if n > MaxBodyBytes {
		return ErrBodyTooLarge
	}
	if n == 0 {
		return nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return fmt.Errorf("httpwire: read body: %w", err)
	}
	r.Body = body
	return nil
}

// readLine reads one CRLF-terminated line, echoing the raw bytes into head.
func readLine(br *bufio.Reader, head *bytes.Buffer) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	head.WriteString(line)
	return strings.TrimRight(line, "\r\n"), nil
}

// originForm strips scheme and authority from an absolute-form request-target.
func originForm(target string) string {
	for _, scheme := range []string{"http://", "https://"} {
		if len(target) >= len(scheme) && strings.EqualFold(target[:len(scheme)], scheme) {
			rest := target[len(scheme):]
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				return rest[i:]
			}
			return "/"
		}
	}
	return target
}

// hasToken reports whether a comma-separated header value contains a token.
func hasToken(value, token string) bool {
	for _, t := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(t), token) {
			return true
		}
	}
	return false
}

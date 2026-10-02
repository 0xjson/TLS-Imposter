package forward

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/json/caido-awesome-tls/helper/internal/httpwire"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

// Result is an upstream answer, read fully into memory.
type Result struct {
	Code    int
	Reason  string
	Headers []httpwire.Header
	Body    []byte
}

// Headers that are meaningless or illegal once the request is re-framed.
var hopByHop = map[string]bool{
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
	"content-length":    true, // the client sets this from the actual body
}

// Send re-sends req to the configured target and reads the whole response.
//
// The destination comes from cfg, never from the Host header, which is passed
// through untouched so the target sees exactly what the client sent.
func Send(client tls_client.HttpClient, cfg *preamble.Config, req *httpwire.Request) (*Result, error) {
	scheme := "http"
	if cfg.Target.TLS {
		scheme = "https"
	}

	// Opaque carries the request-target verbatim, so no library re-encodes it.
	u := &url.URL{Scheme: scheme, Host: cfg.Addr(), Opaque: req.Target}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	out, err := fhttp.NewRequest(req.Method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("forward: build request: %w", err)
	}
	out.URL = u
	out.Host = req.Get("Host")

	out.Header = make(fhttp.Header)
	order := make([]string, 0, len(req.Headers))
	for _, h := range req.Headers {
		lower := strings.ToLower(h.Name)
		if hopByHop[lower] {
			continue
		}
		out.Header[lower] = append(out.Header[lower], h.Value)
		order = append(order, lower)
	}
	// tls-client matches this key case-sensitively against lowercase names.
	out.Header[fhttp.HeaderOrderKey] = order

	res, err := client.Do(out)
	if err != nil {
		return nil, fmt.Errorf("forward: %w", err)
	}
	defer res.Body.Close()

	payload, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("forward: read response body: %w", err)
	}

	result := &Result{
		Code:   res.StatusCode,
		Reason: reasonOf(res.Status, res.StatusCode),
		Body:   payload,
	}
	// res.Header is a map, so the order the server sent is already lost here.
	// Spec section 12 records that as a known limitation.
	for name := range res.Header {
		if strings.HasPrefix(name, ":") || name == fhttp.HeaderOrderKey {
			continue
		}
		for _, v := range res.Header.Values(name) {
			result.Headers = append(result.Headers, httpwire.Header{Name: name, Value: v})
		}
	}
	return result, nil
}

// reasonOf recovers the reason phrase from a status like "404 Not Found".
func reasonOf(status string, code int) string {
	prefix := fmt.Sprintf("%d ", code)
	if strings.HasPrefix(status, prefix) {
		return status[len(prefix):]
	}
	return fhttp.StatusText(code)
}

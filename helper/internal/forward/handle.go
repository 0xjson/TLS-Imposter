package forward

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/0xjson/tls-imposter/helper/internal/httpwire"
	"github.com/0xjson/tls-imposter/helper/internal/preamble"
)

// RelayFunc takes over a connection for an Upgrade handshake.
type RelayFunc func(conn net.Conn, cfg *preamble.Config, req *httpwire.Request) error

// Handle serves one forward connection: read the preamble once, then serve
// requests until the peer goes away.
//
// Errors reaching the target become HTTP error responses, so they are visible
// in Caido's history. Errors in the preamble or in framing close the
// connection, because at that point no well-formed reply is possible and a
// half-written one would desync the client.
//
// Caido opens a fresh connection per request (Task 1, spec 11.1.1 Q3), so the
// loop below is defensive rather than load-bearing.
func Handle(conn net.Conn, token string, cache *Cache, relay RelayFunc, logf func(string, ...any)) {
	defer conn.Close()

	br := bufio.NewReader(conn)

	cfg, err := preamble.Read(br)
	if err != nil {
		logf("preamble rejected: %v", err)
		return
	}
	if err := cfg.Validate(token); err != nil {
		logf("preamble rejected: %v", err)
		return
	}

	for {
		req, err := httpwire.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				logf("request rejected: %v", err)
			}
			return
		}

		if req.IsUpgrade {
			if relay == nil {
				_ = httpwire.WriteError(conn, 501, "Not Implemented",
					errors.New("upgrade requests are not supported"))
				return
			}
			if err := relay(conn, cfg, req); err != nil {
				logf("relay failed: %v", err)
			}
			return // the relay owns the connection from here
		}

		client, err := cache.Get(cfg)
		if err != nil {
			_ = httpwire.WriteError(conn, 502, "Bad Gateway", err)
			return
		}

		res, err := Send(client, cfg, req)
		if err != nil {
			code, reason := 502, "Bad Gateway"
			if isTimeout(err) {
				code, reason = 504, "Gateway Timeout"
			}
			// WriteError sets Connection: close, so the stream ends here
			// cleanly rather than leaving the client awaiting another request.
			_ = httpwire.WriteError(conn, code, reason, err)
			return
		}

		if err := httpwire.WriteResponse(conn, res.Code, res.Reason, res.Headers, res.Body,
			httpwire.BodyAllowed(req.Method, res.Code)); err != nil {
			logf("write response: %v", err)
			return
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	// tls-client surfaces its own deadline as a plain string.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}

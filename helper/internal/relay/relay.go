// Package relay carries Upgrade handshakes (WebSockets) through untouched,
// under the same ClientHello the forwarder would use.
//
// Rebuilding the request, as package forward does, would destroy the exact
// framing these protocols need, so this path copies bytes instead.
package relay

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/bogdanfinn/utls"

	"github.com/0xjson/tls-imposter/helper/internal/fingerprint"
	"github.com/0xjson/tls-imposter/helper/internal/httpwire"
	"github.com/0xjson/tls-imposter/helper/internal/preamble"
)

// Relay owns conn for the rest of its life: it dials the target, replays the
// original request bytes and then copies in both directions until either side
// closes. It does not close conn; the caller's defer does.
func Relay(conn net.Conn, cfg *preamble.Config, req *httpwire.Request) error {
	spec, err := specFor(cfg)
	if err != nil {
		return err
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	raw, err := net.DialTimeout("tcp", cfg.Addr(), timeout)
	if err != nil {
		return fmt.Errorf("relay: dial %s: %w", cfg.Addr(), err)
	}
	defer raw.Close()

	var upstream net.Conn = raw
	if cfg.Target.TLS {
		// specFor returns nil for a profile with no inspectable spec; uTLS then
		// builds the hello from the named ID and the forceHttp1 argument
		// rewrites its ALPN, which is the one case where that flag applies.
		id := utls.HelloCustom
		if spec == nil {
			p, ok := fingerprint.Lookup(cfg.Profile)
			if !ok {
				return fmt.Errorf("relay: unknown profile %q", cfg.Profile)
			}
			id = p.GetClientHelloId()
		}

		// (conn, config, id, randomExtOrder, forceHttp1, disableHttp3)
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         cfg.ServerName(),
			InsecureSkipVerify: true,
		}, id, false, true, true)

		if spec != nil {
			if err := uconn.ApplyPreset(spec); err != nil {
				return fmt.Errorf("relay: apply client hello: %w", err)
			}
		}
		if err := uconn.Handshake(); err != nil {
			return fmt.Errorf("relay: tls handshake with %s: %w", cfg.Addr(), err)
		}
		defer uconn.Close()
		upstream = uconn
	}

	// Replay the handshake request exactly as the client wrote it. A rewritten
	// Sec-WebSocket-Key would fail the handshake.
	if _, err := upstream.Write(req.Head); err != nil {
		return fmt.Errorf("relay: write upgrade request: %w", err)
	}
	if len(req.Body) > 0 {
		if _, err := upstream.Write(req.Body); err != nil {
			return fmt.Errorf("relay: write body: %w", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyThenHalfClose(upstream, conn) }()
	go func() { defer wg.Done(); copyThenHalfClose(conn, upstream) }()
	wg.Wait()
	return nil
}

// specFor builds the ClientHello for this connection, forcing ALPN to
// http/1.1, which is what browsers offer for WebSockets.
//
// Returns (nil, nil) when the profile exposes no spec: uTLS must then build the
// hello itself from the named ID, because its ToSpec is unimplemented.
func specFor(cfg *preamble.Config) (*utls.ClientHelloSpec, error) {
	var spec *utls.ClientHelloSpec

	switch {
	case cfg.ClientHello != "":
		s, err := fingerprint.SpecFromHex(cfg.ClientHello)
		if err != nil {
			return nil, err
		}
		spec = s
	default:
		if _, ok := fingerprint.Lookup(cfg.Profile); !ok {
			return nil, fmt.Errorf("relay: unknown profile %q", cfg.Profile)
		}
		if !fingerprint.HasDirectSpec(cfg.Profile) {
			return nil, nil
		}
		p, _ := fingerprint.Lookup(cfg.Profile)
		s, err := p.GetClientHelloSpec()
		if err != nil {
			return nil, fmt.Errorf("relay: build client hello for %q: %w", cfg.Profile, err)
		}
		spec = &s
	}

	// The fork's forceHttp1 flag only rewrites ALPN for named presets, not for
	// a HelloCustom spec, so do it here.
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	return spec, nil
}

// copyThenHalfClose copies until EOF, then signals the writer side so the peer
// sees a clean close rather than waiting for a timeout.
func copyThenHalfClose(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = dst.Close()
}

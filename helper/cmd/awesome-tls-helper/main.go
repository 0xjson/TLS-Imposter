// Command awesome-tls-helper forwards HTTP requests with a chosen browser's
// TLS and HTTP/2 fingerprint.
//
// It is started by the Caido plugin and speaks a JSON-lines protocol over
// stdio. It holds no configuration of its own: every forward connection carries
// its own settings, so a restart loses nothing. Closing its stdin shuts it down.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/capture"
	"github.com/json/caido-awesome-tls/helper/internal/control"
	"github.com/json/caido-awesome-tls/helper/internal/fingerprint"
	"github.com/json/caido-awesome-tls/helper/internal/forward"
	"github.com/json/caido-awesome-tls/helper/internal/relay"
)

const version = "0.1.0"

// captureThrottle collapses bursts: a browser opens many connections and each
// one carries the same hello.
const captureThrottle = 2 * time.Second

// clientIdleTTL is how long an unused TLS client is kept so its connections can
// be reused, as a browser's would be.
const clientIdleTTL = 10 * time.Minute

func main() {
	out := control.NewWriter(os.Stdout)

	token, err := newToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate token: %v\n", err)
		os.Exit(1)
	}

	// Loopback only, kernel-assigned port: the helper must never be reachable
	// from the network.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	cache := forward.NewCache(clientIdleTTL)
	defer cache.Close()
	go evictLoop(cache)

	cm := &captureManager{out: out}
	defer cm.stop()

	if err := out.Emit(control.Ready{
		Type:           "ready",
		Port:           ln.Addr().(*net.TCPAddr).Port,
		Token:          token,
		Profiles:       fingerprint.Profiles(),
		DefaultProfile: fingerprint.DefaultProfile(),
		Version:        version,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "emit ready: %v\n", err)
		os.Exit(1)
	}

	go accept(ln, token, cache, out)

	// Returning from ReadCommands means stdin closed: the plugin is gone.
	if err := control.ReadCommands(os.Stdin, cm.handle); err != nil {
		fmt.Fprintf(os.Stderr, "read commands: %v\n", err)
	}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func accept(ln net.Listener, token string, cache *forward.Cache, out *control.Writer) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go forward.Handle(conn, token, cache, relay.Relay, func(format string, args ...any) {
			// Never pass the token here: these messages reach Caido's log file.
			out.Logf("warn", format, args...)
		})
	}
}

func evictLoop(cache *forward.Cache) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		cache.Evict(time.Now())
	}
}

// captureManager owns the optional capture listener.
type captureManager struct {
	mu       sync.Mutex
	out      *control.Writer
	listener *capture.Listener
	lastHex  string
	lastAt   time.Time
}

func (m *captureManager) handle(c control.Command) {
	if c.Type != "capture" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listener != nil {
		_ = m.listener.Close()
		m.listener = nil
	}
	if !c.Enabled {
		_ = m.out.Emit(control.CaptureStatus{Type: "capture-status", State: "stopped"})
		return
	}

	l, err := capture.Start(c.Listen, c.ForwardTo, m.onHello)
	if err != nil {
		_ = m.out.Emit(control.CaptureStatus{
			Type: "capture-status", State: "error", Listen: c.Listen, Error: err.Error(),
		})
		return
	}
	m.listener = l
	_ = m.out.Emit(control.CaptureStatus{
		Type: "capture-status", State: "listening", Listen: l.Addr(),
	})
}

func (m *captureManager) onHello(raw []byte) {
	encoded := hex.EncodeToString(raw)

	m.mu.Lock()
	if encoded == m.lastHex || time.Since(m.lastAt) < captureThrottle {
		m.mu.Unlock()
		return
	}
	m.lastHex, m.lastAt = encoded, time.Now()
	m.mu.Unlock()

	info, err := fingerprint.Analyze(raw)
	if err != nil {
		_ = m.out.Emit(control.CaptureRejected{Type: "capture-rejected", Error: err.Error()})
		return
	}
	// Confirm the hello is replayable before offering it as a fingerprint;
	// otherwise the failure would only surface on the user's next request.
	if _, err := fingerprint.SpecFromRaw(raw); err != nil {
		_ = m.out.Emit(control.CaptureRejected{
			Type: "capture-rejected", Error: err.Error(), JA4: info.JA4,
		})
		return
	}
	_ = m.out.Emit(control.Captured{
		Type:        "captured",
		ClientHello: encoded,
		JA3:         info.JA3,
		JA3Text:     info.JA3Text,
		JA4:         info.JA4,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339),
	})
}

func (m *captureManager) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener != nil {
		_ = m.listener.Close()
		m.listener = nil
	}
}

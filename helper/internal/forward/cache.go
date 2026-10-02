// Package forward re-sends a parsed request through a browser-profiled TLS
// client and turns the answer back into bytes on the wire.
package forward

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/json/caido-awesome-tls/helper/internal/fingerprint"
	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

type entry struct {
	client   tls_client.HttpClient
	lastUsed time.Time
}

// Cache holds one client per distinct configuration so that TLS sessions and
// connections pool the way a browser's do. Building a fresh client per request
// would force a new handshake every time, which is itself an anomalous pattern
// for the WAFs this plugin exists to look ordinary to.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*entry
	ttl     time.Duration
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{entries: make(map[string]*entry), ttl: ttl}
}

func key(c *preamble.Config) string {
	h := sha256.Sum256([]byte(c.ClientHello))
	return fmt.Sprintf("%s|%s|%d", c.Profile, hex.EncodeToString(h[:8]), c.TimeoutSec)
}

func (c *Cache) Get(cfg *preamble.Config) (tls_client.HttpClient, error) {
	k := key(cfg)

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[k]; ok {
		e.lastUsed = time.Now()
		return e.client, nil
	}

	client, err := build(cfg)
	if err != nil {
		// Deliberately not cached: a bad profile must fail every time, not once.
		return nil, err
	}
	c.entries[k] = &entry{client: client, lastUsed: time.Now()}
	return client, nil
}

func build(cfg *preamble.Config) (tls_client.HttpClient, error) {
	profile, ok := fingerprint.Lookup(cfg.Profile)
	if !ok {
		return nil, fmt.Errorf("forward: unknown profile %q", cfg.Profile)
	}

	// A captured ClientHello replaces the TLS layer; the HTTP/2 layer still
	// comes from the named profile, because a hello says nothing about HTTP/2.
	if cfg.ClientHello != "" {
		spec, err := fingerprint.SpecFromHex(cfg.ClientHello)
		if err != nil {
			return nil, err
		}
		profile = fingerprint.WithClientHello(profile, spec)
	}

	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(cfg.TimeoutSec),
		// Load-bearing, not an optimization: fhttp otherwise decompresses the
		// body while leaving Content-Encoding in place, handing Caido a
		// response whose header contradicts its bytes.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{DisableCompression: true}),
	}

	// NewHttpClient with an explicit option list attaches no cookie jar, which
	// is what a proxy wants: the client's own cookies pass through untouched.
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Evict drops entries idle for longer than the TTL.
func (c *Cache) Evict(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.Sub(e.lastUsed) > c.ttl {
			e.client.CloseIdleConnections()
			delete(c.entries, k)
		}
	}
}

func (c *Cache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		e.client.CloseIdleConnections()
		delete(c.entries, k)
	}
}

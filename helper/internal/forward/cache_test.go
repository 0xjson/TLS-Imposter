package forward

import (
	"testing"
	"time"

	"github.com/json/caido-awesome-tls/helper/internal/preamble"
)

func cfg(profile, hello string, timeout int) *preamble.Config {
	return &preamble.Config{
		Target:      preamble.Target{Host: "example.com", Port: 443, TLS: true},
		Profile:     profile,
		ClientHello: hello,
		TimeoutSec:  timeout,
	}
}

func TestCacheReusesOneClientPerConfiguration(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()

	a, err := c.Get(cfg("chrome_150", "", 30))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	b, err := c.Get(cfg("chrome_150", "", 30))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a != b {
		t.Error("identical configurations must share one client, so connections pool like a browser's")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestCacheSeparatesClientsByProfileAndTimeout(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()

	base, err := c.Get(cfg("chrome_150", "", 30))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for name, other := range map[string]*preamble.Config{
		"different profile": cfg("firefox_148", "", 30),
		"different timeout": cfg("chrome_150", "", 60),
	} {
		got, err := c.Get(other)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == base {
			t.Errorf("%s must not share a client", name)
		}
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
}

// A captured hello changes the TLS fingerprint, so it must key separately even
// when the profile name is identical.
func TestCacheSeparatesClientsByCapturedHello(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()

	hello := helloHex(t)
	a, err := c.Get(cfg("chrome_150", "", 30))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	b, err := c.Get(cfg("chrome_150", hello, 30))
	if err != nil {
		t.Fatalf("Get with hello: %v", err)
	}
	if a == b {
		t.Error("a captured hello must not share a client with the bare profile")
	}
}

func TestCacheRejectsUnknownProfile(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()
	if _, err := c.Get(cfg("netscape_4", "", 30)); err == nil {
		t.Error("want error for an unknown profile")
	}
	if c.Len() != 0 {
		t.Errorf("a failed build must not be cached, Len = %d", c.Len())
	}
}

func TestCacheRejectsAnUnusableCapturedHello(t *testing.T) {
	c := NewCache(time.Minute)
	defer c.Close()
	if _, err := c.Get(cfg("chrome_150", "16030100", 30)); err == nil {
		t.Error("want error for a truncated captured hello")
	}
}

func TestCacheEvictsIdleEntries(t *testing.T) {
	c := NewCache(10 * time.Minute)
	defer c.Close()

	if _, err := c.Get(cfg("chrome_150", "", 30)); err != nil {
		t.Fatalf("Get: %v", err)
	}
	c.Evict(time.Now().Add(5 * time.Minute))
	if c.Len() != 1 {
		t.Errorf("entry evicted too early: Len = %d", c.Len())
	}
	c.Evict(time.Now().Add(11 * time.Minute))
	if c.Len() != 0 {
		t.Errorf("idle entry not evicted: Len = %d", c.Len())
	}
}

// Using an entry must refresh it, or a busy client gets evicted mid-use.
func TestCacheGetRefreshesIdleTime(t *testing.T) {
	c := NewCache(10 * time.Minute)
	defer c.Close()

	if _, err := c.Get(cfg("chrome_150", "", 30)); err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Re-fetch, then evict with a cutoff that would have expired the original.
	if _, err := c.Get(cfg("chrome_150", "", 30)); err != nil {
		t.Fatalf("Get: %v", err)
	}
	c.Evict(time.Now().Add(9 * time.Minute))
	if c.Len() != 1 {
		t.Errorf("a recently used entry was evicted: Len = %d", c.Len())
	}
}

func TestCacheCloseEmptiesIt(t *testing.T) {
	c := NewCache(time.Minute)
	if _, err := c.Get(cfg("chrome_150", "", 30)); err != nil {
		t.Fatalf("Get: %v", err)
	}
	c.Close()
	if c.Len() != 0 {
		t.Errorf("Len after Close = %d, want 0", c.Len())
	}
}

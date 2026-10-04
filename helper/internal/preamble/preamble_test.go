package preamble

import (
	"bufio"
	"strings"
	"testing"
)

const tok = "0123456789abcdef"

func read(t *testing.T, s string) (*Config, error) {
	t.Helper()
	return Read(bufio.NewReader(strings.NewReader(s)))
}

func TestReadParsesConfigAndLeavesRemainderIntact(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(
		Magic + `{"token":"` + tok + `","target":{"host":"example.com","port":443,"tls":true},` +
			`"sni":null,"profile":"chrome_150","clientHello":null,"timeoutSec":30}` + "\n" +
			"GET / HTTP/1.1\r\n\r\n"))

	cfg, err := Read(br)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cfg.Target.Host != "example.com" || cfg.Target.Port != 443 || !cfg.Target.TLS {
		t.Errorf("target = %+v", cfg.Target)
	}
	if cfg.Profile != "chrome_150" || cfg.TimeoutSec != 30 {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.SNI != nil {
		t.Errorf("SNI = %v, want nil", *cfg.SNI)
	}
	rest, _ := br.ReadString('\n')
	if rest != "GET / HTTP/1.1\r\n" {
		t.Errorf("remainder = %q; the request must be left for the HTTP reader", rest)
	}
}

func TestReadRejectsBadMagicAndOverlongLine(t *testing.T) {
	if _, err := read(t, "GET / HTTP/1.1\r\n\r\n"); err == nil {
		t.Error("want error for missing magic")
	}
	long := Magic + "{" + strings.Repeat("x", MaxLineLen) + "}\n"
	if _, err := read(t, long); err == nil {
		t.Error("want error for overlong preamble line")
	}
}

// A truncated stream must not block or be mistaken for a valid preamble.
func TestReadRejectsTruncatedInput(t *testing.T) {
	for name, in := range map[string]string{
		"empty": "",
		// Sliced from Magic so renaming the protocol cannot leave this case
		// testing an unrelated string instead of a truncated magic.
		"partial magic":   Magic[:6],
		"magic only":      Magic,
		"no newline":      Magic + `{"token":"x"}`,
		"invalid json":    Magic + "{not json}\n",
		"json not object": Magic + "[1,2,3]\n",
	} {
		if _, err := read(t, in); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestValidateChecksTokenAndFields(t *testing.T) {
	base := func() *Config {
		return &Config{
			Token:      tok,
			Target:     Target{Host: "example.com", Port: 443, TLS: true},
			Profile:    "chrome_150",
			TimeoutSec: 30,
		}
	}
	if err := base().Validate(tok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]func(*Config){
		"wrong token":   func(c *Config) { c.Token = "deadbeef" },
		"empty token":   func(c *Config) { c.Token = "" },
		"token prefix":  func(c *Config) { c.Token = tok[:8] },
		"empty host":    func(c *Config) { c.Target.Host = "" },
		"blank host":    func(c *Config) { c.Target.Host = "   " },
		"port zero":     func(c *Config) { c.Target.Port = 0 },
		"port negative": func(c *Config) { c.Target.Port = -1 },
		"port high":     func(c *Config) { c.Target.Port = 70000 },
		"no profile":    func(c *Config) { c.Profile = "" },
		"timeout 0":     func(c *Config) { c.TimeoutSec = 0 },
		"timeout huge":  func(c *Config) { c.TimeoutSec = 10000 },
		"bad hex":       func(c *Config) { c.ClientHello = "nothex" },
		"odd hex":       func(c *Config) { c.ClientHello = "abc" },
	}
	for name, mutate := range cases {
		c := base()
		mutate(c)
		if err := c.Validate(tok); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestValidateAcceptsAHexClientHello(t *testing.T) {
	c := &Config{
		Token:       tok,
		Target:      Target{Host: "example.com", Port: 443, TLS: true},
		Profile:     "chrome_150",
		TimeoutSec:  30,
		ClientHello: "16030100aa",
	}
	if err := c.Validate(tok); err != nil {
		t.Errorf("valid hex client hello rejected: %v", err)
	}
}

func TestAddrAndServerName(t *testing.T) {
	c := &Config{Target: Target{Host: "example.com", Port: 8443, TLS: true}}
	if got := c.Addr(); got != "example.com:8443" {
		t.Errorf("Addr = %q", got)
	}
	if got := c.ServerName(); got != "example.com" {
		t.Errorf("ServerName = %q", got)
	}

	sni := "override.test"
	c.SNI = &sni
	if got := c.ServerName(); got != "override.test" {
		t.Errorf("ServerName with override = %q", got)
	}

	ip := &Config{Target: Target{Host: "93.184.216.34", Port: 443, TLS: true}}
	if got := ip.ServerName(); got != "" {
		t.Errorf("ServerName for IP literal = %q, want empty (no SNI for IPs)", got)
	}
}

// An IPv6 literal must produce a bracketed address, or Dial parses it wrongly.
func TestAddrBracketsIPv6(t *testing.T) {
	c := &Config{Target: Target{Host: "::1", Port: 443, TLS: true}}
	if got := c.Addr(); got != "[::1]:443" {
		t.Errorf("Addr = %q, want [::1]:443", got)
	}
	if got := c.ServerName(); got != "" {
		t.Errorf("ServerName for an IPv6 literal = %q, want empty", got)
	}
}

// Package preamble parses the out-of-band configuration line the plugin writes
// at the start of every forward connection.
package preamble

import (
	"bufio"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	Magic      = "TLSIMPOSTER/1 "
	MaxLineLen = 64 * 1024
)

type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	TLS  bool   `json:"tls"`
}

type Config struct {
	Token       string  `json:"token"`
	Target      Target  `json:"target"`
	SNI         *string `json:"sni"`
	Profile     string  `json:"profile"`
	ClientHello string  `json:"clientHello"`
	TimeoutSec  int     `json:"timeoutSec"`
}

// Read consumes exactly one preamble line and leaves everything after the
// terminating newline in the reader for the HTTP layer.
func Read(br *bufio.Reader) (*Config, error) {
	prefix, err := br.Peek(len(Magic))
	if err != nil {
		return nil, fmt.Errorf("read preamble: %w", err)
	}
	if string(prefix) != Magic {
		return nil, errors.New("read preamble: bad magic")
	}
	if _, err := br.Discard(len(Magic)); err != nil {
		return nil, err
	}

	line := make([]byte, 0, 512)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read preamble: %w", err)
		}
		if b == '\n' {
			break
		}
		if len(line) >= MaxLineLen {
			return nil, fmt.Errorf("read preamble: line exceeds %d bytes", MaxLineLen)
		}
		line = append(line, b)
	}

	var cfg Config
	if err := json.Unmarshal(line, &cfg); err != nil {
		return nil, fmt.Errorf("read preamble: %w", err)
	}
	return &cfg, nil
}

// Validate authenticates the caller and rejects configurations the forwarder
// could not act on.
func (c *Config) Validate(expectedToken string) error {
	// Constant time, and length-checked first so a prefix cannot pass.
	if len(c.Token) != len(expectedToken) ||
		subtle.ConstantTimeCompare([]byte(c.Token), []byte(expectedToken)) != 1 {
		return errors.New("preamble: token mismatch")
	}
	if strings.TrimSpace(c.Target.Host) == "" {
		return errors.New("preamble: empty target host")
	}
	if c.Target.Port < 1 || c.Target.Port > 65535 {
		return fmt.Errorf("preamble: port %d out of range", c.Target.Port)
	}
	if c.Profile == "" {
		return errors.New("preamble: empty profile")
	}
	if c.TimeoutSec < 1 || c.TimeoutSec > 600 {
		return fmt.Errorf("preamble: timeoutSec %d out of range", c.TimeoutSec)
	}
	if c.ClientHello != "" {
		if _, err := hex.DecodeString(c.ClientHello); err != nil {
			return fmt.Errorf("preamble: clientHello is not hex: %w", err)
		}
	}
	return nil
}

// Addr is the dial target. JoinHostPort brackets IPv6 literals.
func (c *Config) Addr() string {
	return net.JoinHostPort(c.Target.Host, strconv.Itoa(c.Target.Port))
}

// ServerName is the SNI to present: the override when given, otherwise the
// target host, and empty for IP literals, which must not carry SNI.
func (c *Config) ServerName() string {
	if c.SNI != nil {
		return *c.SNI
	}
	if net.ParseIP(c.Target.Host) != nil {
		return ""
	}
	return c.Target.Host
}

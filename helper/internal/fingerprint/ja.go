package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Info holds the fingerprints of a ClientHello, for display.
type Info struct {
	JA3     string `json:"ja3"`
	JA3Text string `json:"ja3Text"`
	JA4     string `json:"ja4"`
}

// Analyze computes JA3 and JA4 for a raw ClientHello record.
func Analyze(raw []byte) (Info, error) {
	p, err := parseClientHello(raw)
	if err != nil {
		return Info{}, err
	}
	text := ja3Text(p)
	return Info{
		JA3:     fmt.Sprintf("%x", md5.Sum([]byte(text))),
		JA3Text: text,
		JA4:     ja4(p),
	}, nil
}

// TLS extension numbers this code reads by name.
const (
	extServerName        uint16 = 0x0000
	extSupportedGroups   uint16 = 0x000a
	extECPointFormats    uint16 = 0x000b
	extSignatureAlgs     uint16 = 0x000d
	extALPN              uint16 = 0x0010
	extSupportedVersions uint16 = 0x002b
)

type parsed struct {
	LegacyVersion     uint16
	Ciphers           []uint16 // GREASE removed, wire order
	Extensions        []uint16 // GREASE removed, wire order
	Curves            []uint16 // GREASE removed
	PointFormats      []uint8
	SigAlgs           []uint16 // wire order, GREASE removed
	SupportedVersions []uint16 // GREASE removed
	ALPN              []string
	HasSNI            bool
}

var errTruncated = errors.New("fingerprint: truncated client hello")

// cursor is a bounds-checked big-endian reader.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || len(c.b) < n {
		c.err = errTruncated
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() int {
	b := c.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (c *cursor) u16() uint16 {
	b := c.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (c *cursor) u24() int {
	b := c.take(3)
	if b == nil {
		return 0
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// isGREASE reports whether a value is a GREASE placeholder (RFC 8701): both
// bytes equal and of the form 0xNaNa.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && byte(v)&0x0f == 0x0a
}

func keepNonGREASE(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// parseClientHello reads the fields JA3 and JA4 are computed from out of a
// complete TLS handshake record.
func parseClientHello(raw []byte) (*parsed, error) {
	c := &cursor{b: raw}

	if t := c.u8(); t != 0x16 {
		if c.err != nil {
			return nil, c.err
		}
		return nil, fmt.Errorf("fingerprint: record type %#02x is not handshake", t)
	}
	c.u16()                // record version
	recLen := int(c.u16()) // record length
	if c.err != nil {
		return nil, c.err
	}
	if len(c.b) < recLen {
		return nil, errTruncated
	}
	c.b = c.b[:recLen] // a ClientHello must fit in one record here

	if t := c.u8(); t != 0x01 {
		if c.err != nil {
			return nil, c.err
		}
		return nil, fmt.Errorf("fingerprint: handshake type %#02x is not client_hello", t)
	}
	bodyLen := c.u24()
	if c.err != nil {
		return nil, c.err
	}
	if len(c.b) < bodyLen {
		return nil, errTruncated
	}
	c.b = c.b[:bodyLen]

	p := &parsed{}
	p.LegacyVersion = c.u16()
	c.take(32)     // random
	c.take(c.u8()) // legacy_session_id

	cipherBytes := c.take(int(c.u16()))
	if c.err != nil {
		return nil, c.err
	}
	if len(cipherBytes)%2 != 0 {
		return nil, errTruncated
	}
	var ciphers []uint16
	for i := 0; i < len(cipherBytes); i += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(cipherBytes[i:i+2]))
	}
	p.Ciphers = keepNonGREASE(ciphers)

	c.take(c.u8()) // legacy_compression_methods
	if c.err != nil {
		return nil, c.err
	}

	// The extensions block is optional in the wire format.
	if len(c.b) == 0 {
		return p, nil
	}
	extBytes := c.take(int(c.u16()))
	if c.err != nil {
		return nil, c.err
	}

	e := &cursor{b: extBytes}
	for len(e.b) > 0 {
		id := e.u16()
		payload := e.take(int(e.u16()))
		if e.err != nil {
			return nil, e.err
		}
		if !isGREASE(id) {
			p.Extensions = append(p.Extensions, id)
		}
		if err := p.readExtension(id, payload); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *parsed) readExtension(id uint16, payload []byte) error {
	d := &cursor{b: payload}
	switch id {
	case extServerName:
		p.HasSNI = true
	case extSupportedGroups:
		b := d.take(int(d.u16()))
		if d.err != nil {
			return d.err
		}
		var groups []uint16
		for i := 0; i+1 < len(b); i += 2 {
			groups = append(groups, binary.BigEndian.Uint16(b[i:i+2]))
		}
		p.Curves = keepNonGREASE(groups)
	case extECPointFormats:
		b := d.take(d.u8())
		if d.err != nil {
			return d.err
		}
		p.PointFormats = append(p.PointFormats, b...)
	case extSignatureAlgs:
		b := d.take(int(d.u16()))
		if d.err != nil {
			return d.err
		}
		var algs []uint16
		for i := 0; i+1 < len(b); i += 2 {
			algs = append(algs, binary.BigEndian.Uint16(b[i:i+2]))
		}
		p.SigAlgs = keepNonGREASE(algs)
	case extALPN:
		b := d.take(int(d.u16()))
		if d.err != nil {
			return d.err
		}
		l := &cursor{b: b}
		for len(l.b) > 0 {
			v := l.take(l.u8())
			if l.err != nil {
				return l.err
			}
			p.ALPN = append(p.ALPN, string(v))
		}
	case extSupportedVersions:
		b := d.take(d.u8())
		if d.err != nil {
			return d.err
		}
		var vers []uint16
		for i := 0; i+1 < len(b); i += 2 {
			vers = append(vers, binary.BigEndian.Uint16(b[i:i+2]))
		}
		p.SupportedVersions = keepNonGREASE(vers)
	}
	return nil
}

// ja3Text builds the JA3 string:
// version,ciphers,extensions,curves,point-formats — decimal, dash-separated.
func ja3Text(p *parsed) string {
	join := func(vs []uint16) string {
		parts := make([]string, len(vs))
		for i, v := range vs {
			parts[i] = strconv.Itoa(int(v))
		}
		return strings.Join(parts, "-")
	}
	formats := make([]string, len(p.PointFormats))
	for i, f := range p.PointFormats {
		formats[i] = strconv.Itoa(int(f))
	}
	return strings.Join([]string{
		strconv.Itoa(int(p.LegacyVersion)),
		join(p.Ciphers),
		join(p.Extensions),
		join(p.Curves),
		strings.Join(formats, "-"),
	}, ",")
}

func ja4(p *parsed) string {
	return ja4a(p) + "_" + ja4b(p) + "_" + ja4c(p)
}

// ja4a is the readable prefix: protocol, version, SNI flag, cipher count,
// extension count, ALPN marker. Always 10 characters.
func ja4a(p *parsed) string {
	version := p.LegacyVersion
	for _, v := range p.SupportedVersions {
		if v > version {
			version = v
		}
	}
	var ver string
	switch version {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	case 0x0300:
		ver = "s3"
	default:
		ver = "00"
	}

	sni := "i"
	if p.HasSNI {
		sni = "d"
	}

	// First and last character of the first ALPN value; "00" when absent.
	alpn := "00"
	if len(p.ALPN) > 0 && len(p.ALPN[0]) > 0 {
		v := p.ALPN[0]
		alpn = string([]byte{v[0], v[len(v)-1]})
	}

	// "t" for TCP: this helper never speaks QUIC.
	return fmt.Sprintf("t%s%s%02d%02d%s", ver, sni,
		cap99(len(p.Ciphers)), cap99(len(p.Extensions)), alpn)
}

func cap99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

// ja4b hashes the sorted cipher list.
func ja4b(p *parsed) string {
	if len(p.Ciphers) == 0 {
		return "000000000000"
	}
	return truncatedSHA256(strings.Join(sortedHex(p.Ciphers), ","))
}

// ja4c hashes the sorted extension list (excluding SNI and ALPN, which are
// already represented in the prefix) joined to the signature algorithms in
// their original order.
func ja4c(p *parsed) string {
	exts := make([]uint16, 0, len(p.Extensions))
	for _, e := range p.Extensions {
		if e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return "000000000000"
	}
	return truncatedSHA256(
		strings.Join(sortedHex(exts), ",") + "_" + strings.Join(hexList(p.SigAlgs), ","))
}

func sortedHex(vs []uint16) []string {
	out := hexList(vs)
	slices.Sort(out)
	return out
}

func hexList(vs []uint16) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = fmt.Sprintf("%04x", v)
	}
	return out
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

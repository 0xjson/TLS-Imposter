package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// --- synthetic ClientHello builder -----------------------------------------
//
// Hand-built so every expectation below is checkable by eye.

type helloOpts struct {
	legacyVersion uint16
	ciphers       []uint16
	sni           string   // "" omits the extension
	alpn          []string // nil omits the extension
	curves        []uint16
	pointFormats  []uint8
	sigAlgs       []uint16
	supportedVers []uint16 // nil omits the extension
	extraExts     []uint16 // emitted as empty extensions, in order
}

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func ext(id uint16, payload []byte) []byte {
	out := append(u16(id), u16(uint16(len(payload)))...)
	return append(out, payload...)
}

func buildHello(o helloOpts) []byte {
	var exts []byte

	if o.sni != "" {
		name := append([]byte{0x00}, u16(uint16(len(o.sni)))...)
		name = append(name, []byte(o.sni)...)
		list := append(u16(uint16(len(name))), name...)
		exts = append(exts, ext(0x0000, list)...)
	}
	if o.curves != nil {
		var b []byte
		for _, c := range o.curves {
			b = append(b, u16(c)...)
		}
		exts = append(exts, ext(0x000a, append(u16(uint16(len(b))), b...))...)
	}
	if o.pointFormats != nil {
		b := append([]byte{byte(len(o.pointFormats))}, o.pointFormats...)
		exts = append(exts, ext(0x000b, b)...)
	}
	if o.sigAlgs != nil {
		var b []byte
		for _, s := range o.sigAlgs {
			b = append(b, u16(s)...)
		}
		exts = append(exts, ext(0x000d, append(u16(uint16(len(b))), b...))...)
	}
	if o.alpn != nil {
		var list []byte
		for _, p := range o.alpn {
			list = append(list, byte(len(p)))
			list = append(list, []byte(p)...)
		}
		exts = append(exts, ext(0x0010, append(u16(uint16(len(list))), list...))...)
	}
	if o.supportedVers != nil {
		var b []byte
		for _, v := range o.supportedVers {
			b = append(b, u16(v)...)
		}
		exts = append(exts, ext(0x002b, append([]byte{byte(len(b))}, b...))...)
	}
	for _, id := range o.extraExts {
		exts = append(exts, ext(id, nil)...)
	}

	var body []byte
	body = append(body, u16(o.legacyVersion)...)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // empty session id
	var ciphers []byte
	for _, c := range o.ciphers {
		ciphers = append(ciphers, u16(c)...)
	}
	body = append(body, u16(uint16(len(ciphers)))...)
	body = append(body, ciphers...)
	body = append(body, 0x01, 0x00) // one compression method: null
	body = append(body, u16(uint16(len(exts)))...)
	body = append(body, exts...)

	// handshake header: type 0x01, 24-bit length
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// record header: handshake(0x16), version, 16-bit length
	rec := append([]byte{0x16}, u16(0x0301)...)
	rec = append(rec, u16(uint16(len(hs)))...)
	return append(rec, hs...)
}

func sampleOpts() helloOpts {
	return helloOpts{
		legacyVersion: 0x0303,
		// 0x0a0a is GREASE and must be excluded everywhere.
		ciphers:       []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b},
		sni:           "example.com",
		alpn:          []string{"h2", "http/1.1"},
		curves:        []uint16{0x1a1a, 0x001d, 0x0017},
		pointFormats:  []uint8{0x00},
		sigAlgs:       []uint16{0x0403, 0x0804, 0x0401},
		supportedVers: []uint16{0x2a2a, 0x0304, 0x0303},
		extraExts:     []uint16{0x0017, 0x002d, 0x7a7a},
	}
}

// --- field parsing ---------------------------------------------------------

func TestParseClientHelloExtractsFieldsAndDropsGREASE(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}

	if p.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion = %#04x", p.LegacyVersion)
	}
	if got, want := fmt.Sprint(p.Ciphers), fmt.Sprint([]uint16{0x1301, 0x1302, 0xc02b}); got != want {
		t.Errorf("Ciphers = %s, want %s (GREASE removed, order kept)", got, want)
	}
	wantExts := []uint16{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b, 0x0017, 0x002d}
	if got, want := fmt.Sprint(p.Extensions), fmt.Sprint(wantExts); got != want {
		t.Errorf("Extensions = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(p.Curves), fmt.Sprint([]uint16{0x001d, 0x0017}); got != want {
		t.Errorf("Curves = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(p.PointFormats), fmt.Sprint([]uint8{0x00}); got != want {
		t.Errorf("PointFormats = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(p.SigAlgs), fmt.Sprint([]uint16{0x0403, 0x0804, 0x0401}); got != want {
		t.Errorf("SigAlgs = %s, want %s (original order)", got, want)
	}
	if got, want := fmt.Sprint(p.SupportedVersions), fmt.Sprint([]uint16{0x0304, 0x0303}); got != want {
		t.Errorf("SupportedVersions = %s, want %s", got, want)
	}
	if !p.HasSNI {
		t.Error("HasSNI = false")
	}
	if got, want := fmt.Sprint(p.ALPN), fmt.Sprint([]string{"h2", "http/1.1"}); got != want {
		t.Errorf("ALPN = %s, want %s", got, want)
	}
}

func TestParseClientHelloHandlesMissingOptionalExtensions(t *testing.T) {
	p, err := parseClientHello(buildHello(helloOpts{
		legacyVersion: 0x0303,
		ciphers:       []uint16{0x1301},
	}))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if p.HasSNI || len(p.ALPN) != 0 || len(p.Curves) != 0 || len(p.SigAlgs) != 0 {
		t.Errorf("absent extensions must yield zero values, got %+v", p)
	}
}

func TestParseClientHelloRejectsTruncatedInput(t *testing.T) {
	full := buildHello(sampleOpts())
	for _, n := range []int{0, 4, 9, 20, len(full) - 1} {
		if _, err := parseClientHello(full[:n]); err == nil {
			t.Errorf("want error for input truncated to %d bytes", n)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x7a7a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0a0b, 0x001d, 0x0000} {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true", v)
		}
	}
}

// --- JA3 -------------------------------------------------------------------

func TestJA3TextAndHash(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}

	// version,ciphers,extensions,curves,pointformats — decimal, GREASE removed.
	const want = "771,4865-4866-49195,0-10-11-13-16-43-23-45,29-23,0"
	if got := ja3Text(p); got != want {
		t.Errorf("ja3Text:\n got %q\nwant %q", got, want)
	}

	info, err := Analyze(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	wantHash := fmt.Sprintf("%x", md5.Sum([]byte(want)))
	if info.JA3 != wantHash {
		t.Errorf("JA3 = %q, want md5 of the JA3 string %q", info.JA3, wantHash)
	}
	if info.JA3Text != want {
		t.Errorf("JA3Text = %q", info.JA3Text)
	}
}

// --- JA4 -------------------------------------------------------------------

func TestJA4APart(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	// t  = TCP
	// 13 = TLS 1.3 (highest in supported_versions, GREASE ignored)
	// d  = SNI present
	// 03 = 3 ciphers after GREASE removal
	// 08 = 8 extensions after GREASE removal, SNI and ALPN included in the count
	// h2 = first and last character of the first ALPN value
	const want = "t13d0308h2"
	if got := ja4a(p); got != want {
		t.Errorf("ja4a = %q, want %q", got, want)
	}
	if len(want) != 10 {
		t.Fatalf("the a-part must be 10 characters, test constant is %d", len(want))
	}
}

func TestJA4APartWithoutSNIorALPNandWithLegacyVersion(t *testing.T) {
	p, err := parseClientHello(buildHello(helloOpts{
		legacyVersion: 0x0303, ciphers: []uint16{0x1301, 0x1302},
	}))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	// i = no SNI; 00 = no ALPN; version falls back to the legacy field (TLS 1.2)
	const want = "t12i020000"
	if got := ja4a(p); got != want {
		t.Errorf("ja4a = %q, want %q", got, want)
	}
}

func TestJA4ALPNUsesFirstAndLastCharacter(t *testing.T) {
	for _, tc := range []struct{ alpn, want string }{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"x", "xx"},
	} {
		o := sampleOpts()
		o.alpn = []string{tc.alpn}
		p, err := parseClientHello(buildHello(o))
		if err != nil {
			t.Fatalf("parseClientHello: %v", err)
		}
		if got := ja4a(p)[8:]; got != tc.want {
			t.Errorf("ALPN %q -> %q, want %q", tc.alpn, got, tc.want)
		}
	}
}

func TestJA4BHashesSortedCipherList(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	const sorted = "1301,1302,c02b"
	sum := sha256.Sum256([]byte(sorted))
	want := hex.EncodeToString(sum[:])[:12]
	if got := ja4b(p); got != want {
		t.Errorf("ja4b = %q, want first 12 hex of sha256(%q) = %q", got, sorted, want)
	}
}

func TestJA4CHashesSortedExtensionsPlusSignatureAlgorithms(t *testing.T) {
	p, err := parseClientHello(buildHello(sampleOpts()))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	// Extensions sorted ascending, with SNI (0000) and ALPN (0010) removed,
	// then an underscore, then the signature algorithms in original order.
	const input = "000a,000b,000d,0017,002b,002d_0403,0804,0401"
	sum := sha256.Sum256([]byte(input))
	want := hex.EncodeToString(sum[:])[:12]
	if got := ja4c(p); got != want {
		t.Errorf("ja4c = %q, want first 12 hex of sha256(%q) = %q", got, input, want)
	}
}

func TestJA4EmptyListsHashToZeros(t *testing.T) {
	p, err := parseClientHello(buildHello(helloOpts{legacyVersion: 0x0303}))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if got := ja4b(p); got != "000000000000" {
		t.Errorf("ja4b with no ciphers = %q, want zeros", got)
	}
	if got := ja4c(p); got != "000000000000" {
		t.Errorf("ja4c with no extensions = %q, want zeros", got)
	}
}

func TestJA4AssemblesThreeUnderscoreSeparatedParts(t *testing.T) {
	raw := buildHello(sampleOpts())
	p, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	want := ja4a(p) + "_" + ja4b(p) + "_" + ja4c(p)

	info, err := Analyze(raw)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if info.JA4 != want {
		t.Errorf("JA4 = %q, want %q", info.JA4, want)
	}
	if n := strings.Count(info.JA4, "_"); n != 2 {
		t.Errorf("JA4 must have exactly two separators, got %d: %q", n, info.JA4)
	}
}

// Counts are two digits and must not overflow the fixed-width a-part.
func TestJA4CountsAreCappedAtNinetyNine(t *testing.T) {
	o := helloOpts{legacyVersion: 0x0303}
	for i := 0; i < 120; i++ {
		o.ciphers = append(o.ciphers, uint16(0x1300+i))
	}
	p, err := parseClientHello(buildHello(o))
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	a := ja4a(p)
	if len(a) != 10 {
		t.Fatalf("a-part = %q, want 10 characters even with 120 ciphers", a)
	}
	if a[4:6] != "99" {
		t.Errorf("cipher count = %q, want capped at 99", a[4:6])
	}
}

// --- real hello ------------------------------------------------------------

func TestAnalyzeAcceptsTheRecordedChromeHello(t *testing.T) {
	info, err := Analyze(loadHello(t))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(info.JA3) != 32 {
		t.Errorf("JA3 = %q, want a 32-character md5 hex digest", info.JA3)
	}
	if !strings.HasPrefix(info.JA4, "t13d") {
		t.Errorf("JA4 = %q, want a TLS 1.3 TCP hello with SNI", info.JA4)
	}
	// Freeze the values once confirmed against an external reporter in Task 19.
	t.Logf("recorded chrome hello: ja3=%s ja4=%s", info.JA3, info.JA4)
}

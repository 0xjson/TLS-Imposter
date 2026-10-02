package fingerprint

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	utls "github.com/bogdanfinn/utls"
)

func loadHello(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/chrome.hello")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("decode testdata: %v", err)
	}
	return raw
}

func TestSpecFromRawParsesARealClientHello(t *testing.T) {
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	if len(spec.CipherSuites) == 0 {
		t.Error("no cipher suites parsed")
	}
	if len(spec.Extensions) == 0 {
		t.Error("no extensions parsed")
	}
}

func TestSpecFromRawReplacesECHWithGREASEPlaceholder(t *testing.T) {
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	for i, ext := range spec.Extensions {
		if g, ok := ext.(*utls.GenericExtension); ok && g.Id == utls.ExtensionECH {
			t.Errorf("extension %d is still a generic ECH extension; real ECH is unsupported "+
				"and must be replaced with a GREASE placeholder", i)
		}
	}
}

func TestSpecFromRawUsesRealPSKResumption(t *testing.T) {
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	for i, ext := range spec.Extensions {
		if _, ok := ext.(*utls.FakePreSharedKeyExtension); ok {
			t.Errorf("extension %d is a fake PSK extension; a fake PSK cannot complete a "+
				"handshake, so resumption must be requested as real", i)
		}
	}
}

func TestSpecFromHexRejectsBadInput(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"spaces":    "   ",
		"non-hex":   "zzzz",
		"truncated": "160301",
	} {
		if _, err := SpecFromHex(in); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestSpecFromHexAcceptsTheRecordedHello(t *testing.T) {
	b, err := os.ReadFile("testdata/chrome.hello")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	spec, err := SpecFromHex(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("SpecFromHex: %v", err)
	}
	if len(spec.CipherSuites) == 0 {
		t.Error("no cipher suites parsed from hex")
	}
}

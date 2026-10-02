// Package fingerprint converts captured ClientHello bytes into uTLS specs and
// resolves the bundled browser profiles. It knows nothing about HTTP framing.
package fingerprint

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	utls "github.com/bogdanfinn/utls"
)

// SpecFromHex parses a hex-encoded ClientHello.
func SpecFromHex(s string) (*utls.ClientHelloSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("fingerprint: empty client hello")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: client hello is not hex: %w", err)
	}
	return SpecFromRaw(raw)
}

// SpecFromRaw converts raw ClientHello bytes (a complete TLS handshake record)
// into a spec uTLS can replay.
func SpecFromRaw(raw []byte) (*utls.ClientHelloSpec, error) {
	if len(raw) < 5 {
		return nil, errors.New("fingerprint: client hello too short to be a TLS record")
	}

	f := &utls.Fingerprinter{
		// Pass unrecognized extensions through, so an unfamiliar browser still
		// reproduces byte-for-byte.
		AllowBluntMimicry: true,
		// Request a usable PSK extension. Without this uTLS yields a "fake" PSK
		// that cannot complete resumption, which the Burp extension works
		// around by swapping the extension out afterwards.
		RealPSKResumption: true,
	}
	spec, err := f.RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: parse client hello: %w", err)
	}

	for i, ext := range spec.Extensions {
		// Real Encrypted ClientHello is not supported; send a GREASE
		// placeholder, which is what a browser with ECH disabled looks like.
		if g, ok := ext.(*utls.GenericExtension); ok && g.Id == utls.ExtensionECH {
			spec.Extensions[i] = utls.BoringGREASEECH()
		}
	}
	return spec, nil
}

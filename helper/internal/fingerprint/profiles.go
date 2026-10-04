package fingerprint

import (
	"maps"
	"slices"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Profiles lists every bundled profile name, sorted.
func Profiles() []string {
	return slices.Sorted(maps.Keys(profiles.MappedTLSClients))
}

// DefaultProfile is the library's current default, which tracks recent Chrome.
// It is resolved through the profile map so the name is always one Lookup
// accepts.
func DefaultProfile() string {
	want := profiles.DefaultClientProfile.GetClientHelloId()
	for name, p := range profiles.MappedTLSClients {
		id := p.GetClientHelloId()
		if id.Client == want.Client && id.Version == want.Version {
			return name
		}
	}
	// Fall back to the newest listed Chrome rather than an unresolvable name.
	names := Profiles()
	for i := len(names) - 1; i >= 0; i-- {
		if len(names[i]) >= 6 && names[i][:6] == "chrome" {
			return names[i]
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func Lookup(name string) (profiles.ClientProfile, bool) {
	p, ok := profiles.MappedTLSClients[name]
	return p, ok
}

// WithClientHello returns base with its TLS ClientHello replaced by spec,
// keeping base's HTTP/2 layer: SETTINGS, their order, connection flow,
// priorities and pseudo-header order. A captured hello says nothing about
// HTTP/2, so that half must still come from a named profile.
func WithClientHello(base profiles.ClientProfile, spec *utls.ClientHelloSpec) profiles.ClientProfile {
	id := utls.ClientHelloID{
		Client:      "TLSImposterCaptured",
		Version:     "1",
		SpecFactory: func() (utls.ClientHelloSpec, error) { return *spec, nil },
	}
	return profiles.NewClientProfile(
		id,
		base.GetSettings(),
		base.GetSettingsOrder(),
		base.GetPseudoHeaderOrder(),
		base.GetConnectionFlow(),
		base.GetPriorities(),
		base.GetHeaderPriority(),
		base.GetStreamID(),
		base.GetAllowHTTP(),
		base.GetHttp3Settings(),
		base.GetHttp3SettingsOrder(),
		base.GetHttp3PriorityParam(),
		base.GetHttp3PseudoHeaderOrder(),
		base.GetHttp3SendGreaseFrames(),
	)
}

// HasDirectSpec reports whether a profile can produce a ClientHelloSpec on its
// own.
//
// Newer profiles carry a SpecFactory and can. Older ones carry a named uTLS
// ClientHelloID whose ToSpec is unimplemented; uTLS resolves those internally
// during the handshake, so they forward correctly but their ClientHello cannot
// be inspected or modified here. The relay uses this to decide between
// replaying a spec with a rewritten ALPN and handing uTLS the named ID with its
// own forceHttp1 flag.
func HasDirectSpec(name string) bool {
	p, ok := Lookup(name)
	if !ok {
		return false
	}
	_, err := p.GetClientHelloSpec()
	return err == nil
}

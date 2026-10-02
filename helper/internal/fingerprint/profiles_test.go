package fingerprint

import (
	"sort"
	"testing"
)

func TestProfilesAreSortedNonEmptyAndContainKnownNames(t *testing.T) {
	got := Profiles()
	if len(got) < 20 {
		t.Fatalf("expected the bundled library's full profile list, got %d", len(got))
	}
	if !sort.StringsAreSorted(got) {
		t.Error("Profiles() must be sorted so the UI dropdown is stable")
	}
	want := map[string]bool{"chrome_150": false, "firefox_148": false, "safari_ios_26_0": false}
	for _, p := range got {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("profile %q missing from Profiles()", name)
		}
	}
}

func TestDefaultProfileIsResolvable(t *testing.T) {
	d := DefaultProfile()
	if d == "" {
		t.Fatal("DefaultProfile() is empty")
	}
	if _, ok := Lookup(d); !ok {
		t.Fatalf("DefaultProfile() = %q, which Lookup rejects", d)
	}
}

func TestLookupRejectsUnknownNames(t *testing.T) {
	if _, ok := Lookup("netscape_4"); ok {
		t.Error("Lookup accepted an unknown profile")
	}
	if _, ok := Lookup(""); ok {
		t.Error("Lookup accepted an empty profile")
	}
}

func TestEveryListedProfileIsUsable(t *testing.T) {
	// A name in the dropdown that cannot be used at all would fail only at
	// request time, on the user's traffic.
	//
	// Two kinds of profile exist. Newer ones carry a SpecFactory, so a spec can
	// be built directly. Older ones carry a named uTLS ClientHelloID whose
	// ToSpec is unimplemented ("please implement this method"); uTLS resolves
	// those internally at handshake time, so they forward fine but cannot have
	// their ALPN rewritten by us. The relay needs that distinction.
	var direct, namedOnly int
	for _, name := range Profiles() {
		p, ok := Lookup(name)
		if !ok {
			t.Errorf("%s: listed but Lookup rejects it", name)
			continue
		}
		if HasDirectSpec(name) {
			direct++
			continue
		}
		namedOnly++
		// Must at least carry a named ID uTLS can resolve on its own.
		if id := p.GetClientHelloId(); id.Client == "" {
			t.Errorf("%s: no direct spec AND no named ClientHelloID; unusable", name)
		}
	}
	if direct == 0 {
		t.Error("no profile can produce a spec directly; the relay would never work")
	}
	t.Logf("%d profiles expose a spec directly, %d resolve via a named uTLS ID",
		direct, namedOnly)
}

func TestHasDirectSpecAgreesWithGetClientHelloSpec(t *testing.T) {
	for _, name := range Profiles() {
		p, _ := Lookup(name)
		_, err := p.GetClientHelloSpec()
		if got, want := HasDirectSpec(name), err == nil; got != want {
			t.Errorf("%s: HasDirectSpec = %v, but GetClientHelloSpec err = %v", name, got, err)
		}
	}
}

func TestDefaultProfileExposesASpecDirectly(t *testing.T) {
	// The default is what most users send, and the relay must be able to force
	// its ALPN to http/1.1 for WebSockets.
	if !HasDirectSpec(DefaultProfile()) {
		t.Errorf("DefaultProfile() = %q cannot produce a spec directly", DefaultProfile())
	}
}

func TestWithClientHelloKeepsTheHTTP2LayerOfTheBase(t *testing.T) {
	base, ok := Lookup("chrome_150")
	if !ok {
		t.Fatal("chrome_150 missing")
	}
	spec, err := SpecFromRaw(loadHello(t))
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	custom := WithClientHello(base, spec)

	if len(custom.GetSettings()) != len(base.GetSettings()) {
		t.Error("HTTP/2 SETTINGS must come from the base profile")
	}
	if got, want := custom.GetConnectionFlow(), base.GetConnectionFlow(); got != want {
		t.Errorf("connection flow = %d, want %d", got, want)
	}
	ph, bph := custom.GetPseudoHeaderOrder(), base.GetPseudoHeaderOrder()
	if len(ph) != len(bph) {
		t.Fatalf("pseudo-header order length = %d, want %d", len(ph), len(bph))
	}
	for i := range bph {
		if ph[i] != bph[i] {
			t.Errorf("pseudo-header %d = %q, want %q", i, ph[i], bph[i])
		}
	}
	if custom.GetClientHelloId().Client == base.GetClientHelloId().Client {
		t.Error("the custom profile must carry its own ClientHelloID, not the base one")
	}

	// The custom profile's hello must be the captured one, not the base's.
	customSpec, err := custom.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("custom GetClientHelloSpec: %v", err)
	}
	if len(customSpec.CipherSuites) != len(spec.CipherSuites) {
		t.Errorf("custom hello has %d ciphers, want the captured %d",
			len(customSpec.CipherSuites), len(spec.CipherSuites))
	}
}

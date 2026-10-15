package fingerprint

import (
	"net"
	"testing"

	utls "github.com/bogdanfinn/utls"
)

// helloRecord marshals the ClientHello a profile would send, as a full TLS
// record, the way cmd/hellogen does.
func helloRecord(t *testing.T, name string) []byte {
	t.Helper()
	p, ok := Lookup(name)
	if !ok {
		t.Fatalf("%s missing", name)
	}
	spec, err := p.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("%s GetClientHelloSpec: %v", name, err)
	}
	// BuildHandshakeState wants a non-nil conn; it is never written to.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := utls.UClient(c1, &utls.Config{ServerName: "tls.peet.ws"}, utls.HelloCustom, false, false, false)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	hs := u.HandshakeState.Hello.Raw
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestFirefox158MatchesTheMeasuredBrowser(t *testing.T) {
	info, err := Analyze(helloRecord(t, "firefox_158"))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Reported by tls.peet.ws for a real Firefox 158.0 on Windows.
	const (
		wantJA3 = "9d42e90b0225e779f03141ddcd699df2"
		wantJA4 = "t13d1517h2_8daaf6152771_3cbfd9057e0d"
	)
	if info.JA3 != wantJA3 {
		t.Errorf("JA3 = %q, want the measured %q\n%s", info.JA3, wantJA3, info.JA3Text)
	}
	if info.JA4 != wantJA4 {
		t.Errorf("JA4 = %q, want the measured %q", info.JA4, wantJA4)
	}
}

func TestFirefox158KeepsTheHTTP2LayerOfFirefox148(t *testing.T) {
	got, _ := Lookup("firefox_158")
	base, _ := Lookup("firefox_148")
	if got.GetConnectionFlow() != base.GetConnectionFlow() {
		t.Errorf("connection flow = %d, want %d", got.GetConnectionFlow(), base.GetConnectionFlow())
	}
	if len(got.GetSettings()) != len(base.GetSettings()) {
		t.Error("HTTP/2 SETTINGS differ from firefox_148")
	}
	if id := got.GetClientHelloId(); id.Client != "Firefox" || id.Version != "158" {
		t.Errorf("ClientHelloID = %s/%s, want Firefox/158", id.Client, id.Version)
	}
}

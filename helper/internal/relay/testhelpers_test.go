package relay

import (
	"os"
	"strings"
	"testing"
)

// helloHex returns the recorded Chrome ClientHello as hex.
func helloHex(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../fingerprint/testdata/chrome.hello")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return strings.TrimSpace(string(b))
}

package capture

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// helloRecord builds a TLS handshake record of the given payload length.
func helloRecord(payloadLen int) []byte {
	payload := make([]byte, payloadLen)
	payload[0] = 0x01 // handshake type: client_hello
	n := payloadLen - 4
	payload[1], payload[2], payload[3] = byte(n>>16), byte(n>>8), byte(n)
	for i := 4; i < payloadLen; i++ {
		payload[i] = byte(i % 251)
	}
	rec := []byte{0x16, 0x03, 0x01, byte(payloadLen >> 8), byte(payloadLen)}
	return append(rec, payload...)
}

func TestSniffFindsTheHelloAfterAConnectPreamble(t *testing.T) {
	hello := helloRecord(512)
	stream := append([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"), hello...)

	got, err := Sniff(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Errorf("got %d bytes, want the %d-byte record", len(got), len(hello))
	}
}

// oneByteReader delivers a single byte per Read, the worst case for a reader
// that assumes Read fills its buffer. The Burp extension's sniffer uses bare
// Read calls and truncates here.
type oneByteReader struct{ b []byte }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	p[0] = r.b[0]
	r.b = r.b[1:]
	return 1, nil
}

func TestSniffSurvivesSingleByteReads(t *testing.T) {
	hello := helloRecord(700)
	got, err := Sniff(&oneByteReader{b: append([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), hello...)})
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Errorf("got %d bytes, want %d — a partial read truncated the hello",
			len(got), len(hello))
	}
}

// Review Focus 5: a browser proxying a plain HTTP site sends no ClientHello.
// Sniff must finish at EOF rather than block.
func TestSniffReturnsErrNoHelloOnPlaintextHTTP(t *testing.T) {
	plain := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"

	done := make(chan error, 1)
	go func() {
		_, err := Sniff(strings.NewReader(plain))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNoHello) {
			t.Errorf("err = %v, want ErrNoHello", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sniff blocked on a stream containing no ClientHello")
	}
}

func TestSniffIgnoresAByteThatMerelyLooksLikeARecordHeader(t *testing.T) {
	// 0x16 followed by bytes that are not a plausible handshake must not be
	// mistaken for a record.
	hello := helloRecord(300)
	noise := []byte{0x16, 0xff, 0xff, 0x00, 0x05, 0x99, 0x99, 0x99, 0x99, 0x99}
	got, err := Sniff(bytes.NewReader(append(noise, hello...)))
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Error("sniffer locked onto noise instead of the real hello")
	}
}

// A record that is a handshake but not a ClientHello must be skipped.
func TestSniffSkipsOtherHandshakeMessages(t *testing.T) {
	other := helloRecord(200)
	other[5] = 0x0b // certificate, not client_hello
	hello := helloRecord(300)

	got, err := Sniff(bytes.NewReader(append(other, hello...)))
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Error("sniffer returned a non-ClientHello handshake record")
	}
}

func TestSniffRejectsATruncatedRecord(t *testing.T) {
	hello := helloRecord(512)
	if _, err := Sniff(bytes.NewReader(hello[:100])); err == nil {
		t.Error("want an error for a record that ends early")
	}
}

// A record claiming an implausible length must not be accepted.
func TestSniffRejectsImplausibleLengths(t *testing.T) {
	// Length 3: below the minimum a ClientHello could possibly be.
	tiny := []byte{0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x00, 0x00}
	if _, err := Sniff(bytes.NewReader(tiny)); !errors.Is(err, ErrNoHello) {
		t.Errorf("err = %v, want ErrNoHello for an implausibly short record", err)
	}
}

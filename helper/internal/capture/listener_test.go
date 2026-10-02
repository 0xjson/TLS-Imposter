package capture

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// echoBackend stands in for Caido's proxy port.
func echoBackend(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return ln
}

func TestListenerPassesBytesThroughAndReportsTheHello(t *testing.T) {
	backend := echoBackend(t)

	captured := make(chan []byte, 1)
	l, err := Start("127.0.0.1:0", backend.Addr().String(), func(h []byte) {
		select {
		case captured <- h:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	hello := helloRecord(400)
	payload := append([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), hello...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The echo backend proves bytes reached it unmodified.
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("bytes were modified in transit; the capture path must be transparent")
	}

	select {
	case h := <-captured:
		if !bytes.Equal(h, hello) {
			t.Errorf("captured %d bytes, want %d", len(h), len(hello))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hello was never reported")
	}
}

// Review Focus 5, at the listener level.
func TestListenerDoesNotBlockPlaintextTraffic(t *testing.T) {
	backend := echoBackend(t)

	l, err := Start("127.0.0.1:0", backend.Addr().String(), func([]byte) {
		t.Error("onHello must not fire for plaintext traffic")
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := []byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(req))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("plaintext traffic was blocked: %v", err)
	}
	if !bytes.Equal(got, req) {
		t.Error("plaintext bytes were modified")
	}
}

// A large upload must not stall when the sniffer has already finished.
func TestListenerKeepsFlowingAfterTheHelloIsCaptured(t *testing.T) {
	backend := echoBackend(t)

	l, err := Start("127.0.0.1:0", backend.Addr().String(), func([]byte) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	hello := helloRecord(400)
	bulk := bytes.Repeat([]byte("A"), 256*1024)
	payload := append(append([]byte("CONNECT h:443 HTTP/1.1\r\n\r\n"), hello...), bulk...)

	go func() { _, _ = conn.Write(payload) }()

	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("bulk traffic stalled after capture: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("bulk bytes were modified")
	}
}

func TestStartRejectsABusyPortAndCloseIsIdempotent(t *testing.T) {
	backend := echoBackend(t)

	l, err := Start("127.0.0.1:0", backend.Addr().String(), func([]byte) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := Start(l.Addr(), backend.Addr().String(), func([]byte) {}); err == nil {
		t.Error("want an error when the listen address is already in use")
	}
	if err := l.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close must be a no-op, got: %v", err)
	}
}

func TestStartRequiresACallback(t *testing.T) {
	if _, err := Start("127.0.0.1:0", "127.0.0.1:1", nil); err == nil {
		t.Error("want an error when onHello is nil")
	}
}

// If Caido is not reachable the browser connection must close rather than hang.
func TestListenerClosesWhenTheBackendIsUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()

	l, err := Start("127.0.0.1:0", dead, func([]byte) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("want the connection closed when the backend is unreachable")
	}
}

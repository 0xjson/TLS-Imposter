package capture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Listener accepts browser connections, forwards them to Caido and reports the
// first ClientHello seen on each.
type Listener struct {
	ln        net.Listener
	forwardTo string
	onHello   func([]byte)
	closeOnce sync.Once
	closed    chan struct{}
}

func Start(listen, forwardTo string, onHello func([]byte)) (*Listener, error) {
	if onHello == nil {
		return nil, errors.New("capture: onHello is required")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("capture: listen on %s: %w", listen, err)
	}
	l := &Listener{ln: ln, forwardTo: forwardTo, onHello: onHello, closed: make(chan struct{})}
	go l.accept()
	return l, nil
}

func (l *Listener) Addr() string { return l.ln.Addr().String() }

func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.ln.Close()
	})
	return err
}

func (l *Listener) accept() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // closed, or unrecoverable
		}
		go l.handle(conn)
	}
}

func (l *Listener) handle(client net.Conn) {
	defer client.Close()

	upstream, err := net.Dial("tcp", l.forwardTo)
	if err != nil {
		// Closing is the right signal: the browser retries or reports a proxy
		// error rather than hanging.
		return
	}
	defer upstream.Close()

	// A pipe fed by a TeeReader lets the sniffer observe the browser's bytes
	// while they are copied onward, so the capture path stays byte-for-byte
	// transparent.
	pr, pw := io.Pipe()
	go func() {
		// Whatever happens, keep draining: an unread pipe applies back pressure
		// to the TeeReader and would stall the connection once the sniffer has
		// finished or given up.
		defer func() { _, _ = io.Copy(io.Discard, pr) }()

		hello, err := Sniff(pr)
		if err != nil {
			// ErrNoHello is ordinary: plaintext traffic carries no hello.
			return
		}
		l.onHello(hello)
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, io.TeeReader(client, pw))
		// Closing the writer ends the sniffer's read with EOF.
		_ = pw.Close()
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

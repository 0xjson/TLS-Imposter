// Command hellogen writes a real browser ClientHello, as a full TLS record in
// hex, for use as fingerprint test data. Not part of the shipped helper.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

func main() {
	spec, err := profiles.Chrome_150.GetClientHelloSpec()
	if err != nil {
		panic(err)
	}
	// A real conn is not needed to marshal the hello, but BuildHandshakeState
	// wants a non-nil one, so give it a socket that goes nowhere.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 65536)
			_, _ = c.Read(buf)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	defer raw.Close()

	// (conn, config, id, randomExtOrder, forceHttp1, disableHttp3)
	u := utls.UClient(raw, &utls.Config{ServerName: "example.com"}, utls.HelloCustom, false, false, false)
	if err := u.ApplyPreset(&spec); err != nil {
		panic(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		panic(err)
	}
	hs := u.HandshakeState.Hello.Raw
	if len(hs) == 0 {
		panic("empty hello")
	}
	// Hello.Raw is the handshake message only. utls's Fingerprinter documents
	// that it wants the FULL TLS record, which is also what the capture
	// listener sees on the wire, so prepend the record header.
	if len(hs) > 0xffff {
		panic("hello too large for one record")
	}
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	fmt.Fprintln(os.Stdout, hex.EncodeToString(append(rec, hs...)))
}

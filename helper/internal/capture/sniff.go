// Package capture sits between the browser and Caido, passing bytes through
// untouched while recording the browser's own ClientHello.
package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrNoHello means the stream ended without a ClientHello. That is ordinary:
// a browser proxying a plaintext site never sends one.
var ErrNoHello = errors.New("capture: stream ended before a client hello")

const (
	recordTypeHandshake   = 0x16
	handshakeTypeHello    = 0x01
	maxHelloRecordPayload = 1 << 14 // TLS record limit
	// 4-byte handshake header + 2-byte version + 32-byte random is the floor
	// for anything that could be a ClientHello.
	minHelloRecordPayload = 4 + 2 + 32
)

// Sniff scans for the first TLS handshake record carrying a ClientHello and
// returns the complete record, header included.
//
// Every multi-byte read uses io.ReadFull: a bare Read may return fewer bytes
// than asked for, which silently truncates the hello.
func Sniff(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)

	for {
		// Resynchronize on a candidate record type byte.
		b, err := br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, ErrNoHello
			}
			return nil, fmt.Errorf("capture: %w", err)
		}
		if b != recordTypeHandshake {
			continue
		}

		peeked, err := br.Peek(4) // version(2) + length(2)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, ErrNoHello
			}
			return nil, fmt.Errorf("capture: %w", err)
		}
		// Peek aliases bufio's internal buffer, which the Discard and ReadFull
		// below invalidate. Copy before reading on, or the reconstructed record
		// header is whatever happens to occupy those bytes afterwards.
		header := make([]byte, 4)
		copy(header, peeked)

		if header[0] != 0x03 { // every TLS version starts 0x03xx
			continue
		}
		length := int(binary.BigEndian.Uint16(header[2:4]))
		if length < minHelloRecordPayload || length > maxHelloRecordPayload {
			continue
		}

		if _, err := br.Discard(4); err != nil {
			return nil, fmt.Errorf("capture: %w", err)
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, fmt.Errorf("capture: read record of %d bytes: %w", length, err)
		}
		if payload[0] != handshakeTypeHello {
			continue // some other handshake message; keep looking
		}

		record := make([]byte, 0, 5+length)
		record = append(record, recordTypeHandshake, header[0], header[1], header[2], header[3])
		return append(record, payload...), nil
	}
}

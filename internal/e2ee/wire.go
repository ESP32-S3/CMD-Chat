package e2ee

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The CMDC2 wire format.
//
// Everything — handshake flights and encrypted records alike — travels as a
// single length-prefixed frame:
//
//	uint32be length || length bytes
//
// A fixed prefix rather than a JSON stream matters here for two reasons. It
// gives the transcript an unambiguous byte string to hash, which a re-encoded
// JSON object does not; and it bounds an allocation before it happens, so a
// hostile relay cannot make a client reserve 4 GiB by sending a header.

// MaxFrameSize bounds one frame. A chat message is capped at 4 KiB by the chat
// layer and a roster is small, so 64 KiB is generous while keeping the largest
// allocation an attacker can force to something a phone can absorb.
const MaxFrameSize = 64 << 10

// Handshake message types.
const (
	msgInit   byte = 1
	msgResp   byte = 2
	msgFinish byte = 3
)

// Errors the wire layer reports. Callers must treat all of them as fatal to the
// connection: there is no resynchronisation point in a stream cipher.
var (
	// ErrFrameTooLarge means a peer announced a frame beyond MaxFrameSize.
	ErrFrameTooLarge = errors.New("e2ee: frame exceeds the maximum size")
	// ErrMalformed means a frame could not be parsed as the message it claimed
	// to be. It is returned for every structural fault, without saying which,
	// so it cannot be used to probe the parser.
	ErrMalformed = errors.New("e2ee: malformed protocol message")
)

// writeFrame writes one length-prefixed frame.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one length-prefixed frame.
//
// The length is checked BEFORE the buffer is allocated. Reversing those two
// steps is the classic way to turn a framing layer into a memory-exhaustion
// primitive for whoever is on the other end of the socket.
func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// reader is a minimal big-endian cursor over a frame.
//
// It never panics and never returns a slice that outlives the frame's bounds:
// every read is checked, and a short frame produces ErrMalformed rather than a
// truncated value that later code would treat as real.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail() { r.err = ErrMalformed }

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.fail()
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// lp reads a uint32-length-prefixed byte string.
func (r *reader) lp() []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	// Bound the claimed length by what is actually left, so a forged length
	// cannot make take() allocate or index past the frame.
	if uint64(n) > uint64(len(r.b)) {
		r.fail()
		return nil
	}
	return r.take(int(n))
}

// done reports whether the frame parsed cleanly AND was fully consumed.
//
// Requiring full consumption is deliberate: trailing bytes after a well-formed
// message are the shape of a smuggling attack, where two implementations
// disagree about where a message ends. CMDC2 rejects them.
func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(r.b))
	}
	return nil
}

// appendU16 and friends keep the encoders readable.
func appendU16(dst []byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return append(dst, b[:]...)
}

func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

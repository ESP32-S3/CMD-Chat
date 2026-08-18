package e2ee

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// This file holds the thin wrappers CMDC1 uses over standard primitives. It
// implements no cryptography of its own: every function here is a call into
// crypto/* or golang.org/x/crypto with the arguments spelled out so a reviewer
// can check them.

const (
	// keySize is the ChaCha20-Poly1305 key length, and also the output size of
	// SHA-256, of the chain keys and of the root key.
	keySize = chacha20poly1305.KeySize // 32

	// nonceSize is the ChaCha20-Poly1305 nonce length.
	nonceSize = chacha20poly1305.NonceSize // 12

	// tagSize is the Poly1305 authentication tag length.
	tagSize = chacha20poly1305.Overhead // 16
)

// lengthPrefix appends lp(b) = uint32be(len(b)) || b to dst.
//
// Every variable-length field that goes into a transcript hash or a signed
// message goes through this. Without it, H(a || b) could collide with
// H(a' || b') for different splits, and a signature over one message would be a
// valid signature over another.
func lengthPrefix(dst, b []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	dst = append(dst, n[:]...)
	return append(dst, b...)
}

// hashTranscript returns H(prev || lp(next)), the transcript step used
// throughout the handshake.
func hashTranscript(prev []byte, next []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(next)))
	h.Write(n[:])
	h.Write(next)
	return h.Sum(nil)
}

// hkdfExtract is HKDF-Extract with SHA-256: PRK = HMAC(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte { return hkdf.Extract(sha256.New, ikm, salt) }

// hkdfExpand is HKDF-Expand with SHA-256.
//
// info is the domain-separation label, and every caller passes a constant from
// labels.go (optionally with a transcript hash appended, which is itself a
// fixed-length value and so cannot be confused with a different label).
func hkdfExpand(prk []byte, info []byte, out int) ([]byte, error) {
	buf := make([]byte, out)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, info), buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// hkdfExpandLabel is hkdfExpand with a string label, for the common case.
func hkdfExpandLabel(prk []byte, label string, out int) ([]byte, error) {
	return hkdfExpand(prk, []byte(label), out)
}

// hmacSHA256 is HMAC-SHA-256(key, data).
func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// aead builds a ChaCha20-Poly1305 AEAD from a 32-byte key.
func aead(key []byte) (interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}, error,
) {
	if len(key) != keySize {
		return nil, errors.New("e2ee: bad AEAD key length")
	}
	return chacha20poly1305.New(key)
}

// context builds the byte string that a signature or a confirmation MAC covers:
//
//	label || 0x00 || transcript || identityPublicKey || lp(id)
//
// The 0x00 separator means a label can never run into the transcript, and the
// length prefix on the ID means a long ID cannot borrow bytes from whatever
// followed it.
func context(label string, transcript, identityPub []byte, id string) []byte {
	out := make([]byte, 0, len(label)+1+len(transcript)+len(identityPub)+4+len(id))
	out = append(out, label...)
	out = append(out, 0x00)
	out = append(out, transcript...)
	out = append(out, identityPub...)
	return lengthPrefix(out, []byte(id))
}

// padBlock is the granularity CMDC1 pads plaintext to.
//
// It trades bandwidth for a coarser length signal. A one-character "hi" and a
// 200-character paragraph produce identically sized records; a 4 KiB message
// still looks different from a 20-byte one. This narrows what a network observer
// learns, and does not pretend to remove it.
const padBlock = 256

// pad applies ISO/IEC 7816-4 padding: append 0x80, then 0x00 until the length
// is a multiple of padBlock. Always adds at least one byte, so unpadding is
// unambiguous.
func pad(plaintext []byte) []byte {
	n := len(plaintext) + 1
	if r := n % padBlock; r != 0 {
		n += padBlock - r
	}
	out := make([]byte, n)
	copy(out, plaintext)
	out[len(plaintext)] = 0x80
	return out
}

// errPadding reports a plaintext whose padding is not well-formed. It is
// deliberately indistinguishable to a caller from any other decryption failure.
var errPadding = errors.New("e2ee: malformed record padding")

// unpad reverses pad.
//
// This runs only on plaintext that has ALREADY passed the Poly1305 check, so an
// attacker cannot use it as an oracle: it never sees a padding error without
// first forging a valid tag.
func unpad(padded []byte) ([]byte, error) {
	i := len(padded) - 1
	for i >= 0 && padded[i] == 0x00 {
		i--
	}
	if i < 0 || padded[i] != 0x80 {
		return nil, errPadding
	}
	return padded[:i], nil
}

// Wipe overwrites a byte slice with zeros.
//
// Honest limitations, because this is Go:
//
//   - The garbage collector may have copied the backing array during a stack
//     growth or a slice append before Wipe ran. Those copies cannot be reached
//     and are not overwritten.
//   - The compiler is permitted to elide stores to memory it can prove is dead.
//     runtime.KeepAlive below stops it proving that for this slice, which is why
//     the call is there; it is not decoration.
//   - Nothing here touches swap, hibernation files, core dumps, or a debugger
//     attached to the live process.
//
// So Wipe shortens the window in which a key sits in reachable heap memory. It
// does not make key material unrecoverable from a compromised machine, and
// SECURITY.md says so. It is applied where the window is long enough to matter:
// message keys after use, chain keys after they ratchet, and the handshake
// secret once the session is running.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// wipeAll is Wipe over several buffers, ignoring nils.
func wipeAll(bufs ...[]byte) {
	for _, b := range bufs {
		if b != nil {
			Wipe(b)
		}
	}
}

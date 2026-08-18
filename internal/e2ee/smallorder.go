package e2ee

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
)

// Small-order and non-canonical Ed25519 public keys are refused.
//
// # Why this is here
//
// crypto/ed25519 follows RFC 8032, which does NOT require an implementation to
// reject a small-order public key. With the all-zero key — the encoding of the
// identity point — an all-zero signature verifies against any message. A peer
// could therefore present that key, sign nothing, and pass the signature check.
//
// It could not impersonate anyone with it: the claimed ID must be the one the
// key derives, so the only identity it wins is
// "cc-" || base32(SHA-256(zeros)[0:10]) — an ID that ANYONE could equally claim,
// because no private key is needed. That is a degenerate identity rather than a
// break of someone else's, but it is exactly the kind of hole that turns into a
// real one when combined with something else later, and the fix costs one
// constant-time comparison against a fixed list.
//
// # The list
//
// These are the eight small-order points of Curve25519's Edwards form together
// with the non-canonical encodings of the identity and of points at the field
// boundary. It is the same blocklist libsodium applies, expressed as raw
// little-endian encodings.
//
// This is a data check, not a cryptographic implementation: no arithmetic is
// performed here.
var smallOrderEd25519 = mustDecodeKeys(
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
)

func mustDecodeKeys(encodings ...string) [][]byte {
	out := make([][]byte, 0, len(encodings))
	for _, e := range encodings {
		b, err := hex.DecodeString(e)
		if err != nil || len(b) != ed25519.PublicKeySize {
			// A typo in the table above is a programming error, and one that
			// would silently weaken the check. Fail loudly at init.
			panic("e2ee: malformed small-order key table entry " + e)
		}
		out = append(out, b)
	}
	return out
}

// usableIdentityKey reports whether a public key is acceptable as a long-term
// identity key.
//
// The comparison is constant-time out of habit rather than necessity: the list
// is public and so is the key, so there is no secret to leak here. Doing it this
// way means nobody has to work that out again when reading the code.
func usableIdentityKey(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	blocked := 0
	for _, bad := range smallOrderEd25519 {
		blocked |= subtle.ConstantTimeCompare(pub, bad)
	}
	return blocked == 0
}

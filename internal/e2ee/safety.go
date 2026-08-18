package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Safety numbers: the answer to "what protects the FIRST exchange?"
//
// # The problem
//
// Everything else in CMDC1 is cryptographic. This is not, and it cannot be.
//
// On first contact there is nothing in the trust store to compare a peer's key
// against. CMD-Chat closes most of that gap by making the ID a hash of the
// public key: a user who typed or pasted a friend's "cc-…" ID has, without
// realising it, already committed to that friend's exact key, and the handshake
// refuses anything else. An attacker cannot substitute its own key for an ID
// the user typed, because it would have to find a second preimage of a
// truncated SHA-256.
//
// What that does NOT cover is the case where the ID itself reached the user
// through a channel the attacker controls — a chat app the attacker reads, a
// web page it can rewrite, a message it can edit in flight. If the attacker
// hands over ITS ID instead of the friend's, every check in this package will
// pass, because the user really is talking to the identity they were given.
//
// No protocol can fix that on its own. The only fix is for the two humans to
// compare something over a channel the attacker does not control — reading it
// aloud on a phone call, or looking at each other's screens.
//
// # What this is
//
// A short string derived from BOTH long-term identity keys, identical on both
// ends and different for every pair. If the two people see the same safety
// number, they are in the same conversation with each other, and there is
// nobody between them. If the numbers differ, there is.
//
// It is deliberately independent of the session: it depends only on the two
// identity keys, so it does not change on every reconnect and a user can learn
// to recognise it.
//
// This is the same idea as Signal's safety numbers and OTR's fingerprints. It
// is not a new construction.

// safetyLabel domain-separates this hash from every other use of the identity
// keys, so a safety number can never be mistaken for, or replayed as, a
// protocol value.
const safetyLabel = protocolName + " " + versionTag + " safety number"

// SafetyNumberGroups is how many groups the rendered number has.
const SafetyNumberGroups = 8

// SafetyNumber renders the verification code for a pair of identity keys.
//
// The two keys are sorted before hashing, so both ends produce the SAME string
// without having to agree on who is the host — which matters, because in
// CMD-Chat either side may be the one that dialled.
//
// Returns "" if either key is not a well-formed Ed25519 public key, so a caller
// can never display a safety number for something that was never authenticated.
func SafetyNumber(local, remote ed25519.PublicKey) string {
	if len(local) != ed25519.PublicKeySize || len(remote) != ed25519.PublicKeySize {
		return ""
	}
	first, second := local, remote
	if bytes.Compare(first, second) > 0 {
		first, second = second, first
	}

	h := sha256.New()
	h.Write([]byte(safetyLabel))
	h.Write([]byte{0x00})
	h.Write(first)
	h.Write(second)
	sum := h.Sum(nil)

	// 20 bytes is 160 bits, which base32 renders as exactly 32 characters: eight
	// groups of four. Long enough that guessing a matching pair is hopeless,
	// short enough that two people will actually read it out.
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:20])

	var b strings.Builder
	size := len(encoded) / SafetyNumberGroups
	for i := range SafetyNumberGroups {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(encoded[i*size : (i+1)*size])
	}
	return b.String()
}

// SafetyNumberFor is SafetyNumber for a completed session.
func (s *Session) SafetyNumber(local ed25519.PublicKey) string {
	return SafetyNumber(local, s.peer.PublicKey)
}

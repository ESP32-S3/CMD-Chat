package e2ee

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// Both people must see the same string, whichever of them dialled.
func TestSafetyNumberIsTheSameOnBothSides(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)

	fromAlice := SafetyNumber(alice.PublicKey, bob.PublicKey)
	fromBob := SafetyNumber(bob.PublicKey, alice.PublicKey)

	if fromAlice == "" {
		t.Fatal("no safety number was produced")
	}
	if fromAlice != fromBob {
		t.Fatalf("the two ends see different safety numbers:\n  %s\n  %s", fromAlice, fromBob)
	}
}

// A different pair must produce a different number, or comparing it proves
// nothing.
func TestSafetyNumberDiffersPerPair(t *testing.T) {
	alice, bob, mallory := testIdent(t), testIdent(t), testIdent(t)

	withBob := SafetyNumber(alice.PublicKey, bob.PublicKey)
	withMallory := SafetyNumber(alice.PublicKey, mallory.PublicKey)

	if withBob == withMallory {
		t.Fatal("two different peers produced the same safety number; a man in the middle would be invisible")
	}
}

// It must be stable: a user who learns it once should recognise it next time.
func TestSafetyNumberIsStable(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	first := SafetyNumber(alice.PublicKey, bob.PublicKey)
	for range 10 {
		if got := SafetyNumber(alice.PublicKey, bob.PublicKey); got != first {
			t.Fatalf("the safety number changed between calls: %q then %q", first, got)
		}
	}
}

// It must be readable out loud: fixed-width groups, no ambiguity.
func TestSafetyNumberIsReadable(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	number := SafetyNumber(alice.PublicKey, bob.PublicKey)

	groups := strings.Fields(number)
	if len(groups) != SafetyNumberGroups {
		t.Fatalf("got %d groups, want %d: %q", len(groups), SafetyNumberGroups, number)
	}
	width := len(groups[0])
	for i, g := range groups {
		if len(g) != width {
			t.Fatalf("group %d is %d characters, the first is %d: %q", i, len(g), width, number)
		}
		for _, r := range g {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", r) {
				t.Fatalf("group %d contains %q, which is not in the base32 alphabet", i, r)
			}
		}
	}
	if bits := len(groups) * width * 5; bits < 128 {
		t.Fatalf("the safety number carries only %d bits", bits)
	}
}

// A malformed key must produce nothing rather than a number that looks real.
func TestSafetyNumberRefusesMalformedKeys(t *testing.T) {
	good := testIdent(t).PublicKey
	for _, bad := range []ed25519.PublicKey{nil, {}, make(ed25519.PublicKey, 31), make(ed25519.PublicKey, 33)} {
		if got := SafetyNumber(good, bad); got != "" {
			t.Fatalf("a malformed key produced %q", got)
		}
		if got := SafetyNumber(bad, good); got != "" {
			t.Fatalf("a malformed key produced %q", got)
		}
	}
}

// The session helper must agree with the standalone function.
func TestSessionSafetyNumberMatches(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr != nil || r.respErr != nil {
		t.Fatalf("handshake: %v / %v", r.initErr, r.respErr)
	}
	defer r.initiator.Close()
	defer r.responder.Close()

	want := SafetyNumber(alice.PublicKey, bob.PublicKey)
	if got := r.initiator.SafetyNumber(alice.PublicKey); got != want {
		t.Fatalf("initiator: got %q, want %q", got, want)
	}
	if got := r.responder.SafetyNumber(bob.PublicKey); got != want {
		t.Fatalf("responder: got %q, want %q", got, want)
	}
}

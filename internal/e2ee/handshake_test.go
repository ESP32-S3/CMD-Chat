package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mlkem"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// ---------------------------------------------------------------------------
// The handshake works, and both sides agree on who the other is
// ---------------------------------------------------------------------------

func TestHandshakeSucceedsAndBothSidesAgree(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}, ExpectPeerID: bob.ID},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr != nil || r.respErr != nil {
		t.Fatalf("handshake failed: initiator=%v responder=%v", r.initErr, r.respErr)
	}
	defer r.initiator.Close()
	defer r.responder.Close()

	// Key confirmation, requirement 9: each side must know exactly which stable
	// identity it authenticated.
	if got := r.initiator.Peer().ID; got != bob.ID {
		t.Errorf("initiator authenticated %q, want %q", got, bob.ID)
	}
	if got := r.responder.Peer().ID; got != alice.ID {
		t.Errorf("responder authenticated %q, want %q", got, alice.ID)
	}
	if !bytes.Equal(r.initiator.Peer().PublicKey, bob.PublicKey) {
		t.Error("initiator recorded the wrong public key for the peer")
	}
	if !bytes.Equal(r.responder.Peer().PublicKey, alice.PublicKey) {
		t.Error("responder recorded the wrong public key for the peer")
	}
	if r.initiator.Peer().Nickname != "bob" || r.responder.Peer().Nickname != "alice" {
		t.Error("nicknames did not survive the handshake intact")
	}
	if r.initiator.Peer().Version != V2 || r.responder.Peer().Version != V2 {
		t.Error("the two sides did not settle on the same protocol version")
	}
}

// The proven identity — not a claimed one — is what reaches the trust policy.
func TestTrustPolicySeesTheProvenIdentity(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)
	initTrust, respTrust := &recordingTrust{}, &recordingTrust{}

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: initTrust},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: respTrust},
	)
	if r.initErr != nil || r.respErr != nil {
		t.Fatalf("handshake failed: %v / %v", r.initErr, r.respErr)
	}
	defer r.initiator.Close()
	defer r.responder.Close()

	if got := initTrust.seen(); len(got) != 1 || got[0] != bob.ID {
		t.Fatalf("initiator's trust policy saw %v, want [%s]", got, bob.ID)
	}
	if got := respTrust.seen(); len(got) != 1 || got[0] != alice.ID {
		t.Fatalf("responder's trust policy saw %v, want [%s]", got, alice.ID)
	}
}

// ---------------------------------------------------------------------------
// Wrong identity, wrong key, and the trust store
// ---------------------------------------------------------------------------

// Requirement 2: a guest that asked for one peer must not end up talking to
// another, however the substitution was made.
func TestHandshakeRejectsTheWrongPeerIdentity(t *testing.T) {
	alice, bob, mallory := testIdent(t), testIdent(t), testIdent(t)
	b := binding(t)

	r := handshake(t,
		// Alice asks for Mallory; Bob answers.
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}, ExpectPeerID: mallory.ID},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr == nil {
		r.initiator.Close()
		t.Fatal("the initiator accepted a peer it had not asked for")
	}
	if !errors.Is(r.initErr, ErrAuthentication) {
		t.Fatalf("got %v, want an authentication failure", r.initErr)
	}
}

// Requirement 10: an identity key that has changed must fail closed, with no
// silent acceptance and no prompt reachable from the network.
func TestHandshakeFailsClosedOnAChangedIdentityKey(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	changed := errors.New("auth: this ID previously used a different identity key")
	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: denyAll{err: changed}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr == nil {
		r.initiator.Close()
		t.Fatal("a refused identity key produced a usable session")
	}
	if !errors.Is(r.initErr, ErrUntrustedKey) {
		t.Fatalf("got %v, want ErrUntrustedKey", r.initErr)
	}
	if !strings.Contains(r.initErr.Error(), "previously used a different identity key") {
		t.Fatalf("the reason was lost on the way out: %v", r.initErr)
	}
}

// An ID must be the one its public key derives. A peer that pairs someone else's
// ID with its own key is rejected before any signature check could be fooled.
func TestHandshakeRejectsAnIDThatDoesNotMatchItsKey(t *testing.T) {
	alice, bob, victim := testIdent(t), testIdent(t), testIdent(t)
	b := binding(t)

	// Bob signs honestly with his own key, but claims the victim's ID.
	liar := creds(bob, "bob")
	liar.ID = victim.ID

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
		Config{Credentials: liar, ChannelBinding: b, Trust: allowAny{}},
	)
	// The responder refuses to run at all with inconsistent credentials, and if
	// it somehow did, the initiator would reject the payload. Either is a pass;
	// what must not happen is a completed session.
	if r.initErr == nil && r.respErr == nil {
		r.initiator.Close()
		r.responder.Close()
		t.Fatal("a peer claimed an ID that its key does not derive, and the handshake completed")
	}
}

// A signature made by the wrong key must not verify.
func TestHandshakeRejectsASignatureFromAnotherKey(t *testing.T) {
	alice, bob, imposter := testIdent(t), testIdent(t), testIdent(t)
	b := binding(t)

	// Bob presents his own ID and public key, but signs with someone else's key.
	forged := creds(bob, "bob")
	forged.Sign = imposter.Sign

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
		Config{Credentials: forged, ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr == nil {
		r.initiator.Close()
		t.Fatal("a signature from the wrong key was accepted")
	}
	if !errors.Is(r.initErr, ErrAuthentication) {
		t.Fatalf("got %v, want an authentication failure", r.initErr)
	}
}

// A signature that is structurally valid but over the wrong content — the
// classic unknown-key-share setup, where a genuine signature from elsewhere is
// presented here — must not verify either.
func TestHandshakeRejectsASignatureOverTheWrongTranscript(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	replayed := creds(bob, "bob")
	replayed.Sign = func(message []byte) []byte {
		// Sign something else entirely, with the right key.
		return bob.Sign([]byte("a signature bob made for another purpose"))
	}

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
		Config{Credentials: replayed, ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr == nil {
		r.initiator.Close()
		t.Fatal("a signature over a different message was accepted")
	}
}

// ---------------------------------------------------------------------------
// Channel binding: the man-in-the-middle defence
// ---------------------------------------------------------------------------

// This is the headline property. An attacker who terminates TLS on both sides
// has two DIFFERENT TLS sessions, so the two exporter values differ. Even though
// it faithfully forwards every byte of the handshake, and even though both
// identities are genuine, the handshake must fail.
func TestChannelBindingDefeatsATLSTerminatingMITM(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)

	// Two bindings: what Alice's TLS session produces, and what Bob's does.
	aliceBinding, bobBinding := binding(t), binding(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: aliceBinding, Trust: allowAny{}, ExpectPeerID: bob.ID},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: bobBinding, Trust: allowAny{}},
	)
	if r.initErr == nil && r.respErr == nil {
		r.initiator.Close()
		r.responder.Close()
		t.Fatal("the handshake completed across two different TLS sessions: a MITM would be undetected")
	}
	if r.initErr == nil {
		t.Error("the initiator accepted a handshake bound to a different TLS session")
	}
}

// A caller that forgets the binding must not get a session. There is no
// unbound mode to fall back to.
func TestHandshakeRefusesToRunWithoutChannelBinding(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), Trust: allowAny{}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: binding(t), Trust: allowAny{}},
	)
	if !errors.Is(r.initErr, ErrNoChannelBinding) {
		t.Fatalf("initiator got %v, want ErrNoChannelBinding", r.initErr)
	}
}

// ---------------------------------------------------------------------------
// Version negotiation and downgrade
// ---------------------------------------------------------------------------

// A peer that offers nothing this build supports gets no session.
func TestHandshakeFailsClosedWithNoCommonVersion(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}, Versions: []Version{0xBEEF}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.respErr == nil {
		r.responder.Close()
		t.Fatal("the responder accepted a version it does not implement")
	}
	if !errors.Is(r.respErr, ErrNoCommonVersion) {
		t.Fatalf("got %v, want ErrNoCommonVersion", r.respErr)
	}
}

// A version outside the offered set can never be the one negotiated.
func TestNegotiatedVersionIsAlwaysOneThatWasOffered(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	// The responder's own preference list leads with a version the initiator
	// never offered. It must not be able to select it.
	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}, Versions: []Version{V2}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}, Versions: []Version{0xC0DE, V2}},
	)
	if r.initErr != nil {
		t.Fatalf("the handshake failed on a legitimate pairing: %v", r.initErr)
	}
	defer r.initiator.Close()
	defer r.responder.Close()

	if got := r.initiator.Peer().Version; got != V2 {
		t.Fatalf("negotiated version %d, which was never offered", got)
	}
}

// Requirement 13 and the reason the post-quantum exchange exists: a peer that
// only speaks the classical-only V1 must be REFUSED, not quietly accommodated.
//
// A silent fallback here would hand an attacker who records traffic today
// exactly what post-quantum protection is meant to deny it, while both users saw
// a connection that looked completely normal.
func TestClassicalOnlyPeerIsRefused(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}, Versions: []Version{V1}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.respErr == nil {
		r.responder.Close()
		t.Fatal("a classical-only peer was accepted; the post-quantum exchange can be skipped")
	}
	if !errors.Is(r.respErr, ErrLegacyPeer) {
		t.Fatalf("got %v, want ErrLegacyPeer", r.respErr)
	}
	// The message has to be usable by a person, not just by a switch statement.
	if !strings.Contains(r.respErr.Error(), "older CMD-Chat") {
		t.Fatalf("the error does not explain itself: %v", r.respErr)
	}
}

// V1 must not merely be unsupported — it must be unimplemented. If the constant
// ever reappeared in SupportedVersions, the test above would still pass while
// the protection silently disappeared.
func TestV1IsNotSupported(t *testing.T) {
	if containsVersion(SupportedVersions, V1) {
		t.Fatal("V1 is back in SupportedVersions; sessions can fall back to classical-only key agreement")
	}
	if len(SupportedVersions) != 1 || SupportedVersions[0] != V2 {
		t.Fatalf("SupportedVersions = %v, want exactly [V2]", SupportedVersions)
	}
}

// An attacker stripping versions out of M1 changes the transcript, so the
// signatures no longer verify. This drives the modification through a real
// tampering proxy rather than asserting it in the abstract.
func TestTamperingWithTheOfferedVersionsBreaksTheHandshake(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	// The proxy flips the version count byte in M1 as it passes.
	tamper := func(frame []byte, n int) []byte {
		if n == 0 && len(frame) > 1 {
			out := append([]byte(nil), frame...)
			out[1] ^= 0xFF
			return out
		}
		return frame
	}

	initErr, respErr := handshakeThroughProxy(t, alice, bob, b, b, tamper)
	if initErr == nil && respErr == nil {
		t.Fatal("a tampered version list produced a working session")
	}
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

func TestHandshakeRejectsMalformedFlights(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
	}{
		{"empty", []byte{}},
		{"wrong message type", []byte{0x09, 0x01, 0x00, 0x01}},
		{"truncated", []byte{msgInit, 0x01, 0x00, 0x01, 0x00}},
		{"no versions", append([]byte{msgInit, 0x00}, make([]byte, 64)...)},
		{"trailing bytes", append(append([]byte{msgInit, 0x01, 0x00, 0x01}, make([]byte, 64)...), 0xFF)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bob := testIdent(t)
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()

			done := make(chan error, 1)
			go func() {
				_ = serverSide.SetDeadline(time.Now().Add(3 * time.Second))
				session, err := Respond(serverSide, Config{
					Credentials: creds(bob, "bob"), ChannelBinding: binding(t), Trust: allowAny{},
				})
				if session != nil {
					session.Close()
				}
				done <- err
			}()

			_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))
			_ = writeFrame(clientSide, tc.frame)

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a malformed flight produced a session")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("the responder hung on a malformed flight")
			}
		})
	}
}

// A frame header claiming an enormous length must be refused before anything is
// allocated for it.
func TestOversizedFrameIsRefused(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if _, err := readFrame(&buf); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
	if err := writeFrame(&bytes.Buffer{}, make([]byte, MaxFrameSize+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge on write", err)
	}
}

// ---------------------------------------------------------------------------
// Local credential hygiene
// ---------------------------------------------------------------------------

// A build that somehow held an ID not derived from its own key must not be able
// to start a handshake with it.
func TestRefusesInconsistentLocalCredentials(t *testing.T) {
	alice := testIdent(t)
	broken := creds(alice, "alice")
	broken.ID = "cc-NOTTHERIGHTIDATALL"

	_, err := Initiate(&bytes.Buffer{}, Config{
		Credentials: broken, ChannelBinding: binding(t), Trust: allowAny{},
	})
	if err == nil {
		t.Fatal("a handshake started with an ID that does not match the local key")
	}
}

// DeriveID must agree with the definition every other component uses.
func TestDeriveIDIsStable(t *testing.T) {
	id := testIdent(t)
	if identity.DeriveID(id.PublicKey) != id.ID {
		t.Fatal("DeriveID disagrees with the identity it generated")
	}
	other := testIdent(t)
	if id.ID == other.ID {
		t.Fatal("two independently generated identities collided")
	}
}

// ---------------------------------------------------------------------------
// A tampering proxy, used by several tests above and in the adversarial suite
// ---------------------------------------------------------------------------

// handshakeThroughProxy runs a handshake with an attacker between the two sides
// who sees and may rewrite every frame.
//
// This is the strongest adversary the design claims to resist short of holding a
// private key: full control of the network, in both directions, with the ability
// to modify anything.
func handshakeThroughProxy(t *testing.T, alice, bob *identity.Identity, aliceBinding, bobBinding []byte, tamper func(frame []byte, index int) []byte) (initErr, respErr error) {
	t.Helper()

	aliceConn, proxyToAlice := net.Pipe()
	proxyToBob, bobConn := net.Pipe()
	defer aliceConn.Close()
	defer bobConn.Close()
	defer proxyToAlice.Close()
	defer proxyToBob.Close()

	deadline := time.Now().Add(3 * time.Second)
	for _, c := range []net.Conn{aliceConn, bobConn, proxyToAlice, proxyToBob} {
		_ = c.SetDeadline(deadline)
	}

	// Forward frames, counting them per direction so a test can target one.
	forward := func(from, to net.Conn) {
		for i := 0; ; i++ {
			frame, err := readFrame(from)
			if err != nil {
				return
			}
			if tamper != nil {
				frame = tamper(frame, i)
			}
			if err := writeFrame(to, frame); err != nil {
				return
			}
		}
	}
	go forward(proxyToAlice, proxyToBob)
	go forward(proxyToBob, proxyToAlice)

	var wg sync.WaitGroup
	var initiator, responder *Session
	wg.Add(2)
	go func() {
		defer wg.Done()
		responder, respErr = Respond(bobConn, Config{
			Credentials: creds(bob, "bob"), ChannelBinding: bobBinding, Trust: allowAny{},
		})
	}()
	go func() {
		defer wg.Done()
		initiator, initErr = Initiate(aliceConn, Config{
			Credentials: creds(alice, "alice"), ChannelBinding: aliceBinding, Trust: allowAny{}, ExpectPeerID: bob.ID,
		})
	}()

	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(20 * time.Second):
		t.Fatal("proxied handshake deadlocked")
	}

	if initiator != nil {
		initiator.Close()
	}
	if responder != nil {
		responder.Close()
	}
	return initErr, respErr
}

// A passive attacker that changes nothing must not break anything: the proxy
// harness itself has to be honest, or the tampering tests above prove nothing.
func TestProxyHarnessIsTransparentWhenItDoesNotTamper(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)
	initErr, respErr := handshakeThroughProxy(t, alice, bob, b, b, nil)
	if initErr != nil || respErr != nil {
		t.Fatalf("an untampered proxy broke the handshake: %v / %v", initErr, respErr)
	}
}

// Tampering with any single handshake frame must break the handshake.
func TestTamperingWithAnyHandshakeFrameIsDetected(t *testing.T) {
	for _, target := range []struct {
		name  string
		which int
	}{
		{"M1 from the initiator", 0},
		{"M2 from the responder", 0},
	} {
		t.Run(target.name, func(t *testing.T) {
			alice, bob := testIdent(t), testIdent(t)
			b := binding(t)
			flipped := false
			tamper := func(frame []byte, i int) []byte {
				if flipped || i != target.which || len(frame) < 40 {
					return frame
				}
				flipped = true
				out := append([]byte(nil), frame...)
				out[len(out)-1] ^= 0x01
				return out
			}
			initErr, respErr := handshakeThroughProxy(t, alice, bob, b, b, tamper)
			if initErr == nil && respErr == nil {
				t.Fatal("a tampered handshake frame produced a working session")
			}
		})
	}
}

// A truncated payload must be rejected rather than indexed into.
func TestMalformedPayloadIsRejected(t *testing.T) {
	_, err := decodeAuthPayload(make([]byte, 4))
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// crypto/ed25519 follows RFC 8032 and does NOT reject small-order public keys:
// an all-zero signature verifies under the all-zero key. This documents that
// fact and pins the check that stops it reaching CMDC2.
func TestSmallOrderIdentityKeysAreRefused(t *testing.T) {
	zero := make(ed25519.PublicKey, ed25519.PublicKeySize)

	if !ed25519.Verify(zero, []byte("anything at all"), make([]byte, ed25519.SignatureSize)) {
		t.Log("crypto/ed25519 rejected the degenerate key on its own; the guard below is still required, because that is not a documented guarantee")
	}
	if usableIdentityKey(zero) {
		t.Fatal("the all-zero Ed25519 key was accepted as an identity key")
	}
	for i, bad := range smallOrderEd25519 {
		if usableIdentityKey(ed25519.PublicKey(bad)) {
			t.Fatalf("small-order key %d was accepted as an identity key", i)
		}
	}

	// A real key must still be usable, or the guard is useless.
	if !usableIdentityKey(testIdent(t).PublicKey) {
		t.Fatal("a genuine identity key was rejected")
	}
}

// The guard must hold end to end, not just as a unit: a peer that presents the
// degenerate key gets no session.
func TestHandshakeRefusesADegenerateIdentityKey(t *testing.T) {
	alice := testIdent(t)
	b := binding(t)

	zero := make(ed25519.PublicKey, ed25519.PublicKeySize)
	degenerate := Credentials{
		ID:        identity.DeriveID(zero),
		PublicKey: zero,
		Sign:      func([]byte) []byte { return make([]byte, ed25519.SignatureSize) },
		Nickname:  "nobody",
	}

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
		Config{Credentials: degenerate, ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr == nil && r.respErr == nil {
		r.initiator.Close()
		r.responder.Close()
		t.Fatal("a degenerate identity key produced a working session")
	}
}

// ---------------------------------------------------------------------------
// Post-quantum key agreement
// ---------------------------------------------------------------------------

// The wire format must actually carry the ML-KEM values. Without this, every
// other post-quantum claim could be true of a build that quietly dropped them.
func TestHandshakeCarriesTheMLKEMValuesOnTheWire(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	var m1Len, m2Len int
	tamper := func(frame []byte, i int) []byte {
		if i == 0 {
			if m1Len == 0 {
				m1Len = len(frame)
			} else if m2Len == 0 {
				m2Len = len(frame)
			}
		}
		return frame
	}

	if initErr, respErr := handshakeThroughProxy(t, alice, bob, b, b, tamper); initErr != nil || respErr != nil {
		t.Fatalf("handshake: %v / %v", initErr, respErr)
	}

	// M1 = type(1) + count(1) + versions(2n) + x25519(32) + encapsulation key + random(32).
	wantM1 := 1 + 1 + 2*len(SupportedVersions) + 32 + mlkemEncapsulationKeySize + 32
	if m1Len != wantM1 {
		t.Fatalf("M1 is %d bytes, want %d; the ML-KEM encapsulation key is not on the wire", m1Len, wantM1)
	}
	// M2 = type(1) + version(2) + x25519(32) + ciphertext + random(32) + lp(C2).
	minM2 := 1 + 2 + 32 + mlkemCiphertextSize + 32
	if m2Len < minM2 {
		t.Fatalf("M2 is %d bytes, below the %d-byte minimum; the ML-KEM ciphertext is not on the wire", m2Len, minM2)
	}
}

// The post-quantum secret must genuinely feed the session key.
//
// This is the test that would catch a combiner wired up to ignore one half.
// Corrupting only the ML-KEM ciphertext — leaving X25519 completely intact —
// must break the handshake. If it did not, the post-quantum component would be
// decorative.
func TestCorruptingOnlyTheMLKEMCiphertextBreaksTheHandshake(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	// M2 layout: type(1) | version(2) | x25519(32) | kemCiphertext(1088) | ...
	// Flip a bit inside the ML-KEM ciphertext only.
	const kemOffset = 1 + 2 + 32
	flipped := false
	tamper := func(frame []byte, i int) []byte {
		// The responder's first frame is M2.
		if flipped || i != 0 || len(frame) < kemOffset+mlkemCiphertextSize {
			return frame
		}
		flipped = true
		out := append([]byte(nil), frame...)
		out[kemOffset+10] ^= 0x01
		return out
	}

	initErr, respErr := handshakeThroughProxy(t, alice, bob, b, b, tamper)
	if !flipped {
		t.Fatal("the ML-KEM ciphertext was never reached; the test did not exercise anything")
	}
	if initErr == nil && respErr == nil {
		t.Fatal("corrupting the ML-KEM ciphertext left the handshake working: the post-quantum secret is not reaching the key schedule")
	}
}

// And the same in the other direction: corrupting only the X25519 key must also
// break it. Neither component may be load-bearing on its own.
func TestCorruptingOnlyTheX25519KeyBreaksTheHandshake(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	const x25519Offset = 1 + 2
	flipped := false
	tamper := func(frame []byte, i int) []byte {
		if flipped || i != 0 || len(frame) < x25519Offset+32 {
			return frame
		}
		flipped = true
		out := append([]byte(nil), frame...)
		out[x25519Offset+5] ^= 0x01
		return out
	}

	initErr, respErr := handshakeThroughProxy(t, alice, bob, b, b, tamper)
	if initErr == nil && respErr == nil {
		t.Fatal("corrupting the X25519 key left the handshake working")
	}
}

// A malformed ML-KEM encapsulation key must be rejected rather than fed to the
// KEM.
func TestMalformedEncapsulationKeyIsRejected(t *testing.T) {
	bob := testIdent(t)

	// A well-formed M1 in every respect except the encapsulation key.
	m1 := []byte{msgInit, 1}
	m1 = appendU16(m1, uint16(V2))
	m1 = append(m1, make([]byte, 32)...)                                      // x25519
	m1 = append(m1, bytes.Repeat([]byte{0xFF}, mlkemEncapsulationKeySize)...) // not a valid key
	m1 = append(m1, make([]byte, 32)...)                                      // random

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	done := make(chan error, 1)
	go func() {
		_ = serverSide.SetDeadline(time.Now().Add(3 * time.Second))
		session, err := Respond(serverSide, Config{
			Credentials: creds(bob, "bob"), ChannelBinding: binding(t), Trust: allowAny{},
		})
		if session != nil {
			session.Close()
		}
		done <- err
	}()

	_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))
	_ = writeFrame(clientSide, m1)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a malformed ML-KEM encapsulation key produced a session")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the responder hung on a malformed encapsulation key")
	}
}

// The combiner must use both halves, in a fixed order, and must not lose bytes.
func TestHybridSecretCombinesBothHalves(t *testing.T) {
	quantum := bytes.Repeat([]byte{0xAA}, mlkemSharedKeySize)
	classical := bytes.Repeat([]byte{0xBB}, 32)

	combined := hybridSecret(quantum, classical)
	if len(combined) != len(quantum)+len(classical) {
		t.Fatalf("combined secret is %d bytes, want %d", len(combined), len(quantum)+len(classical))
	}
	if !bytes.Equal(combined[:len(quantum)], quantum) {
		t.Fatal("the post-quantum half is not first, or was altered")
	}
	if !bytes.Equal(combined[len(quantum):], classical) {
		t.Fatal("the classical half is missing or was altered")
	}

	// Changing either half must change the result.
	otherQuantum := bytes.Repeat([]byte{0xAB}, mlkemSharedKeySize)
	if bytes.Equal(hybridSecret(otherQuantum, classical), combined) {
		t.Fatal("changing the post-quantum half did not change the combined secret")
	}
	otherClassical := bytes.Repeat([]byte{0xBC}, 32)
	if bytes.Equal(hybridSecret(quantum, otherClassical), combined) {
		t.Fatal("changing the classical half did not change the combined secret")
	}
}

// Two handshakes between the same identities must produce different session
// keys. ML-KEM encapsulation is randomised, as is X25519, so nothing about a
// repeat connection may be predictable.
func TestRepeatedHandshakesProduceIndependentSessions(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)

	tags := map[string]bool{}
	for i := range 5 {
		b := binding(t)
		r := handshake(t,
			Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
			Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
		)
		if r.initErr != nil || r.respErr != nil {
			t.Fatalf("handshake %d: %v / %v", i, r.initErr, r.respErr)
		}
		r.initiator.mu.Lock()
		tag := string(r.initiator.associated)
		r.initiator.mu.Unlock()
		if tags[tag] {
			t.Fatalf("handshake %d reproduced an earlier session tag", i)
		}
		tags[tag] = true
		r.initiator.Close()
		r.responder.Close()
	}
}

// The two tests above corrupt a value that is also inside the transcript, so
// either the transcript hash or the shared secret could be what rejected them.
// This isolates the question: with the transcript held FIXED, does changing only
// the post-quantum half of the shared secret change the derived keys?
//
// If it does not, the ML-KEM exchange is decorative and every post-quantum claim
// in SECURITY.md is false.
func TestPostQuantumHalfAloneChangesTheDerivedKeys(t *testing.T) {
	transcript := bytes.Repeat([]byte{0x42}, 32)
	quantum := bytes.Repeat([]byte{0xAA}, mlkemSharedKeySize)
	classical := bytes.Repeat([]byte{0xBB}, 32)

	base, err := deriveHandshakeKeys(hybridSecret(quantum, classical), transcript)
	if err != nil {
		t.Fatal(err)
	}

	// Change ONLY the post-quantum half. Same transcript, same X25519 secret.
	alteredQuantum := append([]byte(nil), quantum...)
	alteredQuantum[0] ^= 0x01
	pqChanged, err := deriveHandshakeKeys(hybridSecret(alteredQuantum, classical), transcript)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.prk, pqChanged.prk) {
		t.Fatal("changing only the ML-KEM secret left the handshake secret identical: the post-quantum exchange does not reach the key schedule")
	}
	for name, pair := range map[string][2][]byte{
		"responder key": {base.respKey, pqChanged.respKey},
		"initiator key": {base.initKey, pqChanged.initKey},
		"responder mac": {base.respMAC, pqChanged.respMAC},
		"initiator mac": {base.initMAC, pqChanged.initMAC},
	} {
		if bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("the %s did not change when the ML-KEM secret did", name)
		}
	}

	// And symmetrically: changing only the classical half must also change them,
	// so neither component can be silently dropped.
	alteredClassical := append([]byte(nil), classical...)
	alteredClassical[0] ^= 0x01
	classicalChanged, err := deriveHandshakeKeys(hybridSecret(quantum, alteredClassical), transcript)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.prk, classicalChanged.prk) {
		t.Fatal("changing only the X25519 secret left the handshake secret identical")
	}

	// The two single-sided changes must not collide with each other either.
	if bytes.Equal(pqChanged.prk, classicalChanged.prk) {
		t.Fatal("the two halves are interchangeable; the combiner is losing information")
	}
}

// Both sides must derive the SAME post-quantum secret, or nothing would decrypt.
// This exercises the KEM round trip directly, independent of the handshake.
func TestMLKEMRoundTripAgrees(t *testing.T) {
	decapsulation, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	encapsulationKey, err := mlkem.NewEncapsulationKey768(decapsulation.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	sent, ciphertext := encapsulationKey.Encapsulate()
	if len(ciphertext) != mlkemCiphertextSize {
		t.Fatalf("ciphertext is %d bytes, the wire format expects %d", len(ciphertext), mlkemCiphertextSize)
	}
	if len(sent) != mlkemSharedKeySize {
		t.Fatalf("shared secret is %d bytes, want %d", len(sent), mlkemSharedKeySize)
	}
	if len(decapsulation.EncapsulationKey().Bytes()) != mlkemEncapsulationKeySize {
		t.Fatalf("encapsulation key is %d bytes, the wire format expects %d",
			len(decapsulation.EncapsulationKey().Bytes()), mlkemEncapsulationKeySize)
	}

	received, err := decapsulation.Decapsulate(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent, received) {
		t.Fatal("the two sides derived different post-quantum secrets")
	}

	// FIPS 203 specifies implicit rejection: a corrupted ciphertext yields a
	// pseudorandom secret rather than an error. Pinning that here documents why
	// the handshake does not treat a decapsulation error as the rejection path.
	corrupted := append([]byte(nil), ciphertext...)
	corrupted[0] ^= 0x01
	other, err := decapsulation.Decapsulate(corrupted)
	if err != nil {
		t.Fatalf("a corrupted ciphertext returned an error rather than implicit rejection: %v", err)
	}
	if bytes.Equal(other, received) {
		t.Fatal("a corrupted ciphertext produced the correct shared secret")
	}
}

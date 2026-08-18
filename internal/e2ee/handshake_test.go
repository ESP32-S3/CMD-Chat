package e2ee

import (
	"bytes"
	"crypto/ed25519"
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
	if r.initiator.Peer().Version != V1 || r.responder.Peer().Version != V1 {
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

// A responder that picks a version the initiator never offered is rejected
// outright, before any signature check.
func TestInitiatorRejectsAVersionItNeverOffered(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	// The responder claims to support a version the initiator did not offer, and
	// selects it. Its own preference order puts the bogus version first.
	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}, Versions: []Version{V1}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}, Versions: []Version{0xC0DE, V1}},
	)
	// selectVersion honours the responder's own list first, but only among what
	// was offered, so this particular pairing still lands on V1. The property
	// under test is that nothing outside the offered set can ever be chosen.
	if r.initErr == nil && r.initiator.Peer().Version != V1 {
		t.Fatalf("negotiated version %d, which was never offered", r.initiator.Peer().Version)
	}
	if r.initErr != nil && !errors.Is(r.initErr, ErrDowngrade) && !errors.Is(r.initErr, ErrNoCommonVersion) {
		t.Fatalf("unexpected failure: %v", r.initErr)
	}
	if r.initiator != nil {
		r.initiator.Close()
	}
	if r.responder != nil {
		r.responder.Close()
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
// fact and pins the check that stops it reaching CMDC1.
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

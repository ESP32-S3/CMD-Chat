package chat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/auth"
	"github.com/ESP32-S3/CMD-Chat/internal/e2ee"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// Adversarial tests: an attacker who controls the relay, and therefore every
// byte on the wire in both directions.
//
// This is the attacker the pre-CMDC2 design lost to. See
// docs/SECURITY-BASELINE.md, weakness W1.

// ---------------------------------------------------------------------------
// The man in the middle
// ---------------------------------------------------------------------------

// mitm is a hostile relay that terminates TLS on both sides.
//
// It behaves exactly like the real relay Worker except that instead of moving
// opaque bytes, it runs its OWN TLS session with each endpoint and forwards the
// decrypted application stream between them. Under the old design this was a
// complete break: it could read every message while both users saw
// "Authenticated host ...".
type mitm struct {
	guestFacing net.Conn // what the guest dials
	hostFacing  net.Conn // what the host accepts
	fingerprint string   // the attacker's own certificate fingerprint

	forwarded int64
	mu        sync.Mutex
}

// newMITM wires an attacker between a guest and a host.
func newMITM(t *testing.T) (attacker *mitm, guestTransport net.Conn, hostTransport net.Conn) {
	t.Helper()

	// The attacker needs a certificate of its own. NewHost makes one.
	attackerIdent := testIdentity(t)
	shell, err := NewHost(attackerIdent.ID, "relay", attackerIdent)
	if err != nil {
		t.Fatalf("attacker certificate: %v", err)
	}

	guestTransport, attackerGuestSide := net.Pipe()
	attackerHostSide, hostTransport := net.Pipe()

	a := &mitm{fingerprint: shell.Fingerprint}

	go func() {
		// Towards the guest, the attacker is the server.
		guestConn := tls.Server(attackerGuestSide, shell.TLSConfig)
		// Towards the host, the attacker is an ordinary client.
		hostConn := tls.Client(attackerHostSide, &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		})

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = guestConn.Handshake() }()
		go func() { defer wg.Done(); _ = hostConn.Handshake() }()
		wg.Wait()

		a.guestFacing, a.hostFacing = guestConn, hostConn

		copyCounting := func(dst io.Writer, src io.Reader) {
			buf := make([]byte, 4096)
			for {
				n, err := src.Read(buf)
				if n > 0 {
					a.mu.Lock()
					a.forwarded += int64(n)
					a.mu.Unlock()
					if _, werr := dst.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}
		go copyCounting(hostConn, guestConn)
		copyCounting(guestConn, hostConn)
	}()

	t.Cleanup(func() {
		_ = attackerGuestSide.Close()
		_ = attackerHostSide.Close()
	})
	return a, guestTransport, hostTransport
}

// This is the central security claim of the redesign.
//
// The attacker holds both TLS sessions. It forwards the CMDC2 handshake
// faithfully. Both identities are genuine and both endpoints behave correctly.
// The handshake must still fail, because the two TLS sessions produce different
// exporter values and the signatures are over transcripts that include them.
func TestTLSTerminatingRelayCannotBecomeAManInTheMiddle(t *testing.T) {
	isolateConfigDir(t)

	hostIdent, guestIdent := testIdentity(t), testIdentity(t)
	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	host.Trust = allowAny{}

	attacker, guestTransport, hostTransport := newMITM(t)

	hostErr := make(chan error, 1)
	go func() {
		conn, err := host.Accept(tls.Server(hostTransport, host.TLSConfig))
		if conn != nil {
			conn.Close()
		}
		hostErr <- err
	}()

	// The worst realistic case: the phonebook is controlled by the same
	// attacker, so the fingerprint the guest pins is the ATTACKER'S. Certificate
	// pinning gives no protection at all here, by construction.
	_, guestErr := Dial(guestTransport, ClientOptions{
		Fingerprint:  attacker.fingerprint,
		ExpectHostID: hostIdent.ID,
		Nickname:     "guestuser",
		Identity:     guestIdent,
		Trust:        allowAny{},
	})

	if guestErr == nil {
		t.Fatal("the guest completed a handshake through a TLS-terminating relay: this is a full man-in-the-middle break")
	}
	t.Logf("guest correctly refused: %v", guestErr)

	// The guest has hung up. Tear the attacker's other leg down too, so the host
	// finds out now rather than sitting out its full handshake deadline.
	_ = hostTransport.Close()

	select {
	case err := <-hostErr:
		if err == nil {
			t.Fatal("the host completed a handshake through a TLS-terminating relay")
		}
		t.Logf("host correctly refused: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("the host neither completed nor refused")
	}

	attacker.mu.Lock()
	forwarded := attacker.forwarded
	attacker.mu.Unlock()
	if forwarded == 0 {
		t.Fatal("the attacker forwarded nothing; the test did not exercise the attack")
	}
	t.Logf("the attacker forwarded %d bytes of handshake and still got nothing", forwarded)
}

// The same attacker, but now the guest also pins the REAL host's fingerprint —
// the case where the phonebook is honest and only the relay is hostile. TLS
// pinning catches this one on its own, and it must.
func TestHostileRelayWithAnHonestPhonebookIsCaughtByPinning(t *testing.T) {
	isolateConfigDir(t)

	hostIdent, guestIdent := testIdentity(t), testIdentity(t)
	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	host.Trust = allowAny{}

	_, guestTransport, hostTransport := newMITM(t)
	go func() {
		conn, _ := host.Accept(tls.Server(hostTransport, host.TLSConfig))
		if conn != nil {
			conn.Close()
		}
	}()

	_, err = Dial(guestTransport, ClientOptions{
		Fingerprint:  host.Fingerprint, // the genuine one
		ExpectHostID: hostIdent.ID,
		Nickname:     "guestuser",
		Identity:     guestIdent,
		Trust:        allowAny{},
	})
	if err == nil {
		t.Fatal("a substituted certificate was accepted")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("got %v, want a fingerprint mismatch", err)
	}
}

// ---------------------------------------------------------------------------
// The relay carries opaque ciphertext, for a whole conversation
// ---------------------------------------------------------------------------

// A stronger version of TestChatOverArbitraryTransportIsOpaque: a full
// back-and-forth conversation, with everything the relay observed checked
// against every plaintext that crossed it.
func TestRelayObservesOnlyCiphertextForAWholeConversation(t *testing.T) {
	isolateConfigDir(t)

	hostIdent, guestIdent := testIdentity(t), testIdentity(t)
	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	host.Trust = allowAny{}

	serverSide, clientSide := net.Pipe()
	tap := &tappedConn{Conn: clientSide}

	accepted := make(chan *Conn, 1)
	go func() {
		conn, err := host.Accept(tls.Server(serverSide, host.TLSConfig))
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	guest, err := Dial(tap, ClientOptions{
		Fingerprint:  host.Fingerprint,
		ExpectHostID: hostIdent.ID,
		Nickname:     "guestuser",
		Identity:     guestIdent,
		Trust:        allowAny{},
	})
	if err != nil {
		t.Fatalf("guest handshake: %v", err)
	}
	defer guest.Close()

	hostConn, ok := <-accepted
	if !ok {
		t.Fatal("host handshake failed")
	}
	defer hostConn.Close()

	secrets := []string{
		"the vault code is 8812",
		"meet me at the usual place",
		"do not tell anyone about this",
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range secrets {
			if _, err := hostConn.Receive(); err != nil {
				t.Errorf("host receive: %v", err)
				return
			}
		}
	}()
	for _, s := range secrets {
		if err := guest.Send(Packet{Type: "msg", Text: s}); err != nil {
			t.Fatalf("guest send: %v", err)
		}
	}
	wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range secrets {
			if _, err := guest.Receive(); err != nil {
				t.Errorf("guest receive: %v", err)
				return
			}
		}
	}()
	for _, s := range secrets {
		if err := hostConn.Send(Packet{Type: "msg", From: hostIdent.ID, Text: s}); err != nil {
			t.Fatalf("host send: %v", err)
		}
	}
	wg.Wait()

	wire := tap.bytesSeen()
	if len(wire) == 0 {
		t.Fatal("the tap saw nothing")
	}
	for _, s := range secrets {
		if bytes.Contains(wire, []byte(s)) {
			t.Fatalf("plaintext %q appeared on the wire", s)
		}
	}
	for _, leak := range []string{hostIdent.ID, guestIdent.ID, "hostuser", "guestuser", "msg"} {
		if bytes.Contains(wire, []byte(leak)) {
			t.Fatalf("%q appeared in cleartext on the wire", leak)
		}
	}
	t.Logf("%d bytes crossed the relay; none of them were plaintext", len(wire))
}

// ---------------------------------------------------------------------------
// Identity key changes, against the real trust store
// ---------------------------------------------------------------------------

// Requirement 10: a known ID that turns up with a new key must fail closed.
func TestTrustStoreFailsClosedOnAKeyChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_peers.json")
	store := auth.LoadFrom(path)

	original, replacement := testIdentity(t), testIdentity(t)

	if err := store.Authorize(original.ID, original.PublicKey); err != nil {
		t.Fatalf("first sighting was refused: %v", err)
	}
	// The same key again is fine.
	if err := store.Authorize(original.ID, original.PublicKey); err != nil {
		t.Fatalf("a repeat sighting was refused: %v", err)
	}
	// A different key for the same ID is not.
	err := store.Authorize(original.ID, replacement.PublicKey)
	if err == nil {
		t.Fatal("a changed identity key was silently accepted")
	}
	if !errors.Is(err, auth.ErrKeyChanged) {
		t.Fatalf("got %v, want ErrKeyChanged", err)
	}

	// It must survive a reload: the refusal cannot depend on process memory.
	reloaded := auth.LoadFrom(path)
	if err := reloaded.Authorize(original.ID, replacement.PublicKey); !errors.Is(err, auth.ErrKeyChanged) {
		t.Fatalf("after reload got %v, want ErrKeyChanged", err)
	}
	if err := reloaded.Authorize(original.ID, original.PublicKey); err != nil {
		t.Fatalf("the original key stopped working after a reload: %v", err)
	}

	// Only a deliberate local act clears it. Nothing on the network can do this.
	if err := reloaded.Forget(original.ID); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if err := reloaded.Authorize(original.ID, replacement.PublicKey); err != nil {
		t.Fatalf("after an explicit Forget the new key was still refused: %v", err)
	}
}

// The key-change refusal must reach the handshake, not just the store.
func TestHandshakeRefusesAPeerWhoseKeyChanged(t *testing.T) {
	isolateConfigDir(t)
	path := filepath.Join(t.TempDir(), "trusted_peers.json")

	hostIdent, guestIdent := testIdentity(t), testIdentity(t)
	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	host.Trust = allowAny{}

	// The guest has previously talked to this ID using a DIFFERENT key.
	store := auth.LoadFrom(path)
	stranger := testIdentity(t)
	if err := store.Authorize(hostIdent.ID, stranger.PublicKey); err != nil {
		t.Fatal(err)
	}

	serverSide, clientSide := net.Pipe()
	go func() {
		conn, _ := host.Accept(tls.Server(serverSide, host.TLSConfig))
		if conn != nil {
			conn.Close()
		}
	}()

	_, err = Dial(clientSide, ClientOptions{
		Fingerprint:  host.Fingerprint,
		ExpectHostID: hostIdent.ID,
		Nickname:     "guestuser",
		Identity:     guestIdent,
		Trust:        store,
	})
	if err == nil {
		t.Fatal("the guest connected to an ID whose key had changed")
	}
	if !strings.Contains(err.Error(), "different identity key") {
		t.Fatalf("got %v, want the key-change reason", err)
	}
}

// ---------------------------------------------------------------------------
// Reconnects, and direct versus relay
// ---------------------------------------------------------------------------

// Requirement 16: a session restart must produce fresh keys, and old ciphertext
// must not be usable against the new session.
func TestReconnectProducesAnIndependentSession(t *testing.T) {
	isolateConfigDir(t)

	hostIdent, guestIdent := testIdentity(t), testIdentity(t)
	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	host.Trust = allowAny{}

	connect := func() (*Conn, *Conn) {
		serverSide, clientSide := net.Pipe()
		accepted := make(chan *Conn, 1)
		go func() {
			conn, err := host.Accept(tls.Server(serverSide, host.TLSConfig))
			if err != nil {
				close(accepted)
				return
			}
			accepted <- conn
		}()
		guest, err := Dial(clientSide, ClientOptions{
			Fingerprint:  host.Fingerprint,
			ExpectHostID: hostIdent.ID,
			Nickname:     "guestuser",
			Identity:     guestIdent,
			Trust:        allowAny{},
		})
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		hostSide, ok := <-accepted
		if !ok {
			t.Fatal("host side failed")
		}
		return hostSide, guest
	}

	firstHost, firstGuest := connect()
	firstRecord, err := firstGuest.session.Encrypt([]byte("from the first session"))
	if err != nil {
		t.Fatal(err)
	}
	firstHost.Close()
	firstGuest.Close()

	secondHost, secondGuest := connect()
	defer secondHost.Close()
	defer secondGuest.Close()

	if _, err := secondHost.session.Decrypt(firstRecord); err == nil {
		t.Fatal("a record from the previous session decrypted after a reconnect")
	}

	// The new session works normally.
	go func() { _ = secondGuest.Send(Packet{Type: "msg", Text: "second session"}) }()
	p, err := secondHost.Receive()
	if err != nil {
		t.Fatalf("receive after reconnect: %v", err)
	}
	if p.Text != "second session" {
		t.Fatalf("got %q", p.Text)
	}
}

// Requirement 16: a direct connection and a relayed one must be
// indistinguishable to the crypto layer. The relay case is modelled by a
// transport that is not a socket at all.
func TestDirectAndRelayedConnectionsAreCryptographicallyIdentical(t *testing.T) {
	isolateConfigDir(t)

	hostIdent, guestIdent := testIdentity(t), testIdentity(t)

	run := func(t *testing.T, wrap func(net.Conn) net.Conn) {
		host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
		if err != nil {
			t.Fatalf("NewHost: %v", err)
		}
		host.Trust = allowAny{}

		serverSide, clientSide := net.Pipe()
		accepted := make(chan *Conn, 1)
		go func() {
			conn, err := host.Accept(tls.Server(serverSide, host.TLSConfig))
			if err != nil {
				close(accepted)
				return
			}
			accepted <- conn
		}()

		guest, err := Dial(wrap(clientSide), ClientOptions{
			Fingerprint:  host.Fingerprint,
			ExpectHostID: hostIdent.ID,
			Nickname:     "guestuser",
			Identity:     guestIdent,
			Trust:        allowAny{},
		})
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		defer guest.Close()

		hostSide, ok := <-accepted
		if !ok {
			t.Fatal("host side failed")
		}
		defer hostSide.Close()

		if hostSide.Peer().ID != guestIdent.ID {
			t.Fatalf("host authenticated %q", hostSide.Peer().ID)
		}
		if guest.Peer().ID != hostIdent.ID {
			t.Fatalf("guest authenticated %q", guest.Peer().ID)
		}

		go func() { _ = guest.Send(Packet{Type: "msg", Text: "same either way"}) }()
		p, err := hostSide.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if p.Text != "same either way" {
			t.Fatalf("got %q", p.Text)
		}
	}

	t.Run("direct", func(t *testing.T) {
		run(t, func(c net.Conn) net.Conn { return c })
	})
	t.Run("relayed", func(t *testing.T) {
		// A tapped connection stands in for a relay that sees everything.
		run(t, func(c net.Conn) net.Conn { return &tappedConn{Conn: c} })
	})
}

// ---------------------------------------------------------------------------
// Garbage on the wire
// ---------------------------------------------------------------------------

// A hostile relay injecting arbitrary bytes must not get anything past the
// record layer, and must not be able to desynchronise a working session by
// trying.
func TestInjectedGarbageIsRejected(t *testing.T) {
	hostSide, guestSide := securePair(t)

	garbage := [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xFF}, 40),
		bytes.Repeat([]byte{0xAA}, 300),
	}
	for i, g := range garbage {
		if _, err := hostSide.session.Decrypt(g); err == nil {
			t.Fatalf("garbage %d was accepted", i)
		}
	}

	// The session still works.
	go func() { _ = guestSide.Send(Packet{Type: "msg", Text: "still fine"}) }()
	p, err := hostSide.Receive()
	if err != nil {
		t.Fatalf("the session was damaged by rejected garbage: %v", err)
	}
	if p.Text != "still fine" {
		t.Fatalf("got %q", p.Text)
	}
}

// e2ee.TLSChannelBinding must refuse anything that is not a completed TLS 1.3
// session, so a caller cannot accidentally run CMDC2 unbound.
func TestChannelBindingRequiresCompletedTLS13(t *testing.T) {
	if _, err := e2ee.TLSChannelBinding(nil); err == nil {
		t.Fatal("a nil connection produced a channel binding")
	}

	_, clientSide := net.Pipe()
	c := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true})
	if _, err := e2ee.TLSChannelBinding(c); err == nil {
		t.Fatal("an unhandshaken connection produced a channel binding")
	}
	_ = clientSide.Close()
}

// A real TLS 1.3 session must yield a binding, and the two ends must agree on
// it. If they did not, no handshake would ever succeed.
func TestChannelBindingMatchesOnBothEndsOfOneSession(t *testing.T) {
	ident := testIdentity(t)
	host, err := NewHost(ident.ID, "hostuser", ident)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	server := tls.Server(serverSide, host.TLSConfig)
	client := tls.Client(clientSide, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true,
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = server.Handshake() }()
	go func() { defer wg.Done(); _ = client.Handshake() }()
	wg.Wait()

	serverBinding, err := e2ee.TLSChannelBinding(server)
	if err != nil {
		t.Fatalf("server binding: %v", err)
	}
	clientBinding, err := e2ee.TLSChannelBinding(client)
	if err != nil {
		t.Fatalf("client binding: %v", err)
	}
	if !bytes.Equal(serverBinding, clientBinding) {
		t.Fatal("the two ends of one TLS session derived different channel bindings")
	}
	if len(serverBinding) != e2ee.ChannelBindingLength {
		t.Fatalf("binding is %d bytes, want %d", len(serverBinding), e2ee.ChannelBindingLength)
	}
	if bytes.Equal(serverBinding, make([]byte, len(serverBinding))) {
		t.Fatal("the channel binding is all zeros")
	}
}

// Two separate TLS sessions must produce different bindings. This is what makes
// the man-in-the-middle detection work at all.
func TestSeparateTLSSessionsProduceDifferentBindings(t *testing.T) {
	ident := testIdentity(t)
	host, err := NewHost(ident.ID, "hostuser", ident)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	bindingFor := func() []byte {
		serverSide, clientSide := net.Pipe()
		defer serverSide.Close()
		defer clientSide.Close()
		server := tls.Server(serverSide, host.TLSConfig)
		client := tls.Client(clientSide, &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = server.Handshake() }()
		go func() { defer wg.Done(); _ = client.Handshake() }()
		wg.Wait()
		b, err := e2ee.TLSChannelBinding(client)
		if err != nil {
			t.Fatalf("binding: %v", err)
		}
		return b
	}

	first, second := bindingFor(), bindingFor()
	if bytes.Equal(first, second) {
		t.Fatal("two different TLS sessions produced the same channel binding; a MITM would be undetectable")
	}
}

// A trust policy is mandatory. A caller cannot accidentally build a session that
// accepts anybody by leaving it out.
func TestHandshakeRequiresATrustPolicy(t *testing.T) {
	var policy e2ee.TrustPolicy
	if policy != nil {
		t.Fatal("nil interface is not nil")
	}
	// Exercised through the real API: e2ee.Config.validate refuses a nil Trust.
	_, err := e2ee.Initiate(&bytes.Buffer{}, e2ee.Config{
		Credentials: e2ee.Credentials{
			ID:        "cc-X",
			PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
			Sign:      func([]byte) []byte { return nil },
		},
		ChannelBinding: make([]byte, e2ee.ChannelBindingLength),
	})
	if err == nil {
		t.Fatal("a handshake started with no trust policy")
	}
}

var _ = identity.DeriveID

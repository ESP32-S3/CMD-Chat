package chat

import (
	"crypto/ed25519"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/e2ee"
)

// allowAny is a trust policy that accepts every proven identity.
//
// Tests that are not about trust-on-first-use use it so they never touch the
// real trusted_peers.json, and so a fresh identity per test is not treated as a
// key change.
type allowAny struct{}

func (allowAny) Authorize(string, ed25519.PublicKey) error { return nil }

// securePair returns a connected host-side and guest-side Conn, with both
// handshakes complete.
func securePair(t *testing.T) (hostSide, guestSide *Conn) {
	t.Helper()
	isolateConfigDir(t)

	hostIdent, guestIdent := testIdentity(t), testIdentity(t)
	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	host.Trust = allowAny{}

	serverSide, clientSide := net.Pipe()

	type accepted struct {
		conn *Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := host.Accept(tls.Server(serverSide, host.TLSConfig))
		done <- accepted{c, err}
	}()

	guestSide, err = Dial(clientSide, ClientOptions{
		Fingerprint:  host.Fingerprint,
		ExpectHostID: hostIdent.ID,
		Nickname:     "guestuser",
		Identity:     guestIdent,
		Trust:        allowAny{},
	})
	if err != nil {
		t.Fatalf("guest handshake: %v", err)
	}

	select {
	case a := <-done:
		if a.err != nil {
			t.Fatalf("host handshake: %v", a.err)
		}
		hostSide = a.conn
	case <-time.After(20 * time.Second):
		t.Fatal("host handshake timed out")
	}

	t.Cleanup(func() {
		_ = guestSide.Close()
		_ = hostSide.Close()
	})
	return hostSide, guestSide
}

// The 4 KiB cap is enforced before a packet is ever encrypted, so an oversized
// message never reaches the ratchet.
func TestSendRejectsOversizedMessage(t *testing.T) {
	_, guest := securePair(t)
	err := guest.Send(Packet{Type: "msg", Text: string(make([]byte, MaxMessageBytes+1))})
	if err == nil {
		t.Fatal("expected oversized message to be rejected")
	}
}

// A message at exactly the cap goes through, end to end.
func TestSendAcceptsMessageAtTheCap(t *testing.T) {
	host, guest := securePair(t)

	text := string(make([]byte, MaxMessageBytes))
	go func() { _ = guest.Send(Packet{Type: "msg", Text: text}) }()

	p, err := host.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if len(p.Text) != MaxMessageBytes {
		t.Fatalf("text length = %d, want %d", len(p.Text), MaxMessageBytes)
	}
}

// Both sides can speak as soon as the handshake finishes. This is what the
// priming record in the CMDC1 handshake exists for: without it the host, which
// speaks first, would have no sending chain.
func TestBothSidesCanSendImmediatelyAfterHandshake(t *testing.T) {
	host, guest := securePair(t)

	if !host.session.CanSend() {
		t.Fatal("the host cannot send straight after the handshake; hello would fail")
	}
	if !guest.session.CanSend() {
		t.Fatal("the guest cannot send straight after the handshake")
	}

	go func() { _ = host.Send(Packet{Type: "hello", From: "host"}) }()
	p, err := guest.Receive()
	if err != nil {
		t.Fatalf("guest receive: %v", err)
	}
	if p.Type != "hello" {
		t.Fatalf("type = %q, want hello", p.Type)
	}
}

// Both sides must agree on the same protocol version, and it must be one this
// build actually supports.
func TestHandshakeAgreesOnAVersion(t *testing.T) {
	host, guest := securePair(t)
	if got := host.session.Peer().Version; got != e2ee.V1 {
		t.Fatalf("host negotiated version %d, want %d", got, e2ee.V1)
	}
	if got := guest.session.Peer().Version; got != e2ee.V1 {
		t.Fatalf("guest negotiated version %d, want %d", got, e2ee.V1)
	}
}

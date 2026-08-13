package chat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// isolateConfigDir points os.UserConfigDir at a temp directory so the trust
// store written during the handshake never touches the real user profile.
func isolateConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)         // Windows
	t.Setenv("XDG_CONFIG_HOME", dir) // Linux
	t.Setenv("HOME", dir)            // macOS / fallback
}

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sum := sha256.Sum256(public)
	return &identity.Identity{
		PrivateKey: private,
		PublicKey:  public,
		ID:         "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]),
	}
}

// tappedConn records every byte that crosses it, which is exactly what a relay
// operator would be able to observe.
type tappedConn struct {
	net.Conn
	mu   sync.Mutex
	seen bytes.Buffer
}

func (c *tappedConn) record(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen.Write(b)
}

func (c *tappedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.record(p[:n])
	return n, err
}

func (c *tappedConn) Write(p []byte) (int, error) {
	c.record(p)
	return c.Conn.Write(p)
}

func (c *tappedConn) bytesSeen() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.seen.Bytes()...)
}

// TestChatOverArbitraryTransportIsOpaque is the security claim behind the relay,
// made concrete: the full CMD-Chat handshake runs over a transport that is not a
// TCP socket, and an observer sitting in the middle of that transport sees only
// ciphertext.
func TestChatOverArbitraryTransportIsOpaque(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	guestIdent := testIdentity(t)

	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	// net.Pipe stands in for the relayed byte pipe: no TCP, no addresses.
	serverSide, clientSide := net.Pipe()
	tap := &tappedConn{Conn: clientSide}

	go host.HandleConn(serverSide)

	const secret = "sealed-envelope-42"

	done := make(chan error, 1)
	go func() {
		conn, dec, err := ClientConn(tap, host.Fingerprint, hostIdent.ID, guestIdent.ID, "guestuser", guestIdent)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		var hello Packet
		if err := dec.Decode(&hello); err != nil {
			done <- err
			return
		}
		if hello.Type != "hello" || hello.From != hostIdent.ID {
			done <- err
			return
		}

		// The host broadcasts once a client is attached; wait for that message.
		//
		// Roster and system packets legitimately arrive first now that a room can
		// hold more than two people, so read past anything that is not a message
		// rather than assuming the next packet is the one under test.
		for range 16 {
			var msg Packet
			if err := dec.Decode(&msg); err != nil {
				done <- err
				return
			}
			if msg.Type != "msg" {
				continue
			}
			if msg.Text != secret {
				t.Errorf("received %q, want %q", msg.Text, secret)
			}
			done <- nil
			return
		}
		t.Error("no message packet arrived within 16 packets")
		done <- nil
	}()

	// Give the handshake time to attach the client before broadcasting.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		host.Mu.Lock()
		attached := len(host.Clients)
		host.Mu.Unlock()
		if attached > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	host.Broadcast(Packet{Type: "msg", From: hostIdent.ID, Name: "hostuser", Text: secret})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client side: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out running the chat handshake over a relayed transport")
	}

	wire := tap.bytesSeen()
	if len(wire) == 0 {
		t.Fatal("tap recorded nothing; the test is not observing the transport")
	}
	if bytes.Contains(wire, []byte(secret)) {
		t.Fatal("plaintext message appeared on the wire: a relay could read chat content")
	}
	// The identities themselves must not leak either; they travel inside the
	// encrypted handshake.
	if bytes.Contains(wire, []byte(hostIdent.ID)) || bytes.Contains(wire, []byte(guestIdent.ID)) {
		t.Fatal("a CMD-Chat ID appeared in cleartext on the wire")
	}
	if bytes.Contains(wire, []byte("hostuser")) || bytes.Contains(wire, []byte("guestuser")) {
		t.Fatal("a user name appeared in cleartext on the wire")
	}
	t.Logf("observed %d bytes on the transport, none of them plaintext", len(wire))
}

// A relayed connection must be pinned just as strictly as a direct one: if the
// certificate does not match what the phonebook published, the client refuses.
func TestClientConnRejectsFingerprintMismatch(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	guestIdent := testIdentity(t)

	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	serverSide, clientSide := net.Pipe()
	go host.HandleConn(serverSide)

	wrong := strings.Repeat("ab", 32)
	_, _, err = ClientConn(clientSide, wrong, hostIdent.ID, guestIdent.ID, "guestuser", guestIdent)
	if err == nil {
		t.Fatal("expected the handshake to fail on a fingerprint mismatch")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("got %v, want a fingerprint mismatch", err)
	}
}

// The host identity is checked as well, so a relay cannot substitute a peer.
func TestClientConnRejectsWrongHostIdentity(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	guestIdent := testIdentity(t)
	impostor := testIdentity(t)

	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	serverSide, clientSide := net.Pipe()
	go host.HandleConn(serverSide)

	_, _, err = ClientConn(clientSide, host.Fingerprint, impostor.ID, guestIdent.ID, "guestuser", guestIdent)
	if err == nil {
		t.Fatal("expected the handshake to fail when the host is not who we asked for")
	}
	if !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("got %v, want an identity mismatch", err)
	}
}

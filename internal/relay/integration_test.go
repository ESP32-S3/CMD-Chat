package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"os"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

func throwawayIdentity(t *testing.T) *identity.Identity {
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

// TestLiveRelayHandshake exercises the deployed relay. Skipped unless
// CMD_CHAT_RELAY_INTEGRATION is set so `go test ./...` stays offline-safe.
func TestLiveRelayHandshake(t *testing.T) {
	if os.Getenv("CMD_CHAT_RELAY_INTEGRATION") == "" {
		t.Skip("set CMD_CHAT_RELAY_INTEGRATION=1 to run against the live relay")
	}

	host := throwawayIdentity(t)
	t.Logf("relay: %s", BaseURL())
	t.Logf("host id: %s", host.ID)

	done := make(chan error, 1)
	go func() {
		t.Log("host: connecting to relay")
		session, err := Listen(BaseURL(), host, 30*time.Second)
		if err != nil {
			t.Logf("host: Listen failed: %v", err)
			done <- err
			return
		}
		t.Logf("host: paired with %s", session.PeerID)
		defer session.Close()

		_ = session.Conn.SetReadDeadline(time.Now().Add(12 * time.Second))
		buf := make([]byte, 16)
		n, err := session.Conn.Read(buf)
		if err != nil {
			t.Logf("host: read failed: %v", err)
			done <- err
			return
		}
		t.Logf("host: received %q", buf[:n])
		if _, err = session.Conn.Write([]byte("pong")); err != nil {
			t.Logf("host: write failed: %v", err)
			done <- err
			return
		}
		t.Log("host: wrote pong")

		// Stay in the session until the guest goes away. Closing straight after
		// a write would tear the pipe down before the reply had been read, which
		// is a race in the test rather than in the relay.
		_ = session.Conn.SetReadDeadline(time.Now().Add(12 * time.Second))
		_, _ = session.Conn.Read(buf)
		done <- nil
	}()

	time.Sleep(3 * time.Second)

	// Surface a host-side failure directly instead of letting it show up as a
	// confusing "no host waiting" on the guest.
	select {
	case err := <-done:
		t.Fatalf("host side failed before the guest connected: %v", err)
	default:
	}

	guest := throwawayIdentity(t)
	session, err := Dial(BaseURL(), host.ID, guest)
	if err != nil {
		t.Fatalf("guest Dial: %v", err)
	}
	defer session.Close()
	t.Logf("guest paired with %s", session.PeerID)

	if _, err := session.Conn.Write([]byte("ping")); err != nil {
		t.Fatalf("guest write: %v", err)
	}
	_ = session.Conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 16)
	n, err := session.Conn.Read(buf)
	if err != nil {
		t.Fatalf("guest read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("guest got %q, want pong", buf[:n])
	}
	if err := <-done; err != nil {
		t.Fatalf("host side: %v", err)
	}
}

// Isolates client->server framing from the relay's forwarding logic.
//
// The relay answers a {"type":"ping"} text frame with {"type":"pong"} without
// involving the other peer, so a successful round trip proves the client's
// masking and framing are correct and points the finger at forwarding instead.
func TestClientFramingReachesServer(t *testing.T) {
	if os.Getenv("CMD_CHAT_RELAY_INTEGRATION") == "" {
		t.Skip("set CMD_CHAT_RELAY_INTEGRATION=1")
	}

	ident := throwawayIdentity(t)
	conn, err := dialWebSocket(websocketURL(BaseURL(), ident.ID), authHeaders(ident, "host", ident.ID), 15*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Drain the initial "waiting".
	if raw, err := conn.nextControl(10 * time.Second); err != nil {
		t.Fatalf("expected a waiting message: %v", err)
	} else {
		t.Logf("initial control: %s", raw)
	}

	if err := conn.writeFrame(opText, []byte(`{"type":"ping"}`)); err != nil {
		t.Fatalf("write text frame: %v", err)
	}

	raw, err := conn.nextControl(10 * time.Second)
	if err != nil {
		t.Fatalf("no reply to ping (client->server framing is broken): %v", err)
	}
	t.Logf("reply: %s", raw)
}

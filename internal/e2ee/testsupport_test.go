package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// Shared fixtures for the CMDC1 test suite.
//
// The handshake is run over net.Pipe rather than over a real TLS connection,
// with the channel binding supplied directly. That is deliberate: it lets a test
// hand the two sides DIFFERENT bindings and prove that the handshake fails,
// which is exactly what a man in the middle terminating TLS on both sides would
// produce and is the property the whole design turns on.

// testIdent makes a fresh, valid identity.
func testIdent(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func creds(id *identity.Identity, nickname string) Credentials {
	return Credentials{ID: id.ID, PublicKey: id.PublicKey, Sign: id.Sign, Nickname: nickname}
}

// allowAny accepts every proven identity.
type allowAny struct{}

func (allowAny) Authorize(string, ed25519.PublicKey) error { return nil }

// denyAll refuses every identity, standing in for a trust store that has seen a
// different key for this ID before.
type denyAll struct{ err error }

func (d denyAll) Authorize(string, ed25519.PublicKey) error {
	if d.err != nil {
		return d.err
	}
	return errors.New("refused")
}

// recordingTrust remembers what it was asked to authorise, so a test can assert
// that the trust policy saw the identity the handshake actually proved.
type recordingTrust struct {
	mu   sync.Mutex
	ids  []string
	keys []ed25519.PublicKey
}

func (r *recordingTrust) Authorize(id string, key ed25519.PublicKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	r.keys = append(r.keys, key)
	return nil
}

func (r *recordingTrust) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...)
}

// binding makes a distinct, TLS-exporter-shaped channel binding.
func binding(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, ChannelBindingLength)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("binding: %v", err)
	}
	return b
}

// pairResult carries both ends of a completed handshake.
type pairResult struct {
	initiator *Session
	responder *Session
	initErr   error
	respErr   error
}

// handshake runs both sides concurrently over net.Pipe and returns whatever came
// back. It never fails the test itself, so a caller can assert on the errors.
func handshake(t *testing.T, initCfg, respCfg Config) pairResult {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	var out pairResult
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = serverSide.SetDeadline(time.Now().Add(3 * time.Second))
		out.responder, out.respErr = Respond(serverSide, respCfg)
	}()
	go func() {
		defer wg.Done()
		_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))
		out.initiator, out.initErr = Initiate(clientSide, initCfg)
	}()

	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(20 * time.Second):
		t.Fatal("handshake deadlocked")
	}
	return out
}

// goodPair is the ordinary case: two fresh identities, one shared binding, an
// accepting trust policy.
func goodPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}, ExpectPeerID: bob.ID},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr != nil {
		t.Fatalf("initiator: %v", r.initErr)
	}
	if r.respErr != nil {
		t.Fatalf("responder: %v", r.respErr)
	}
	t.Cleanup(func() {
		_ = r.initiator.Close()
		_ = r.responder.Close()
	})
	return r.initiator, r.responder
}

// roundTrip sends one message from one session to the other and returns what
// arrived, so ordering tests do not have to repeat the two-step every time.
func roundTrip(t *testing.T, from, to *Session, plaintext string) string {
	t.Helper()
	record, err := from.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt %q: %v", plaintext, err)
	}
	got, err := to.Decrypt(record)
	if err != nil {
		t.Fatalf("decrypt %q: %v", plaintext, err)
	}
	return string(got)
}

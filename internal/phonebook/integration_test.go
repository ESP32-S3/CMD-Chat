package phonebook

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/network"
)

// TestLiveDirectory exercises the real deployed phonebook end to end.
//
// It is skipped by default so `go test ./...` stays hermetic and offline-safe;
// set CMD_CHAT_PHONEBOOK_INTEGRATION=1 to run it. It uses a throwaway identity
// and always unregisters, so it leaves nothing behind in the directory.
func TestLiveDirectory(t *testing.T) {
	if os.Getenv("CMD_CHAT_PHONEBOOK_INTEGRATION") == "" {
		t.Skip("set CMD_CHAT_PHONEBOOK_INTEGRATION=1 to run against the live phonebook")
	}

	baseURL := os.Getenv(BaseURLEnv)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sum := sha256.Sum256(public)
	throwaway := &identity.Identity{
		PrivateKey: private,
		PublicKey:  public,
		ID:         "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]),
	}

	client := New(throwaway, baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Always clean up, even if an assertion fails partway through.
	defer func() {
		if err := client.Unregister(context.Background()); err != nil {
			t.Errorf("cleanup: Unregister: %v", err)
		}
	}()

	port := 38556
	registration, err := client.Register(ctx, Announcement{
		Fingerprint: strings.Repeat("ab", 32),
		Candidates: []Candidate{
			{Kind: KindHost, Transport: "tcp", Address: "192.168.1.42", Port: &port, Priority: 100},
			{Kind: KindServerReflexive, Transport: "udp", Address: "203.0.113.9", Port: intPtr(51820), Priority: 200},
		},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registration.TTL <= 0 {
		t.Fatalf("registration has no TTL: %+v", registration)
	}
	t.Logf("registered %s (ttl=%ds, observed_ip=%s)", throwaway.ID, registration.TTL, registration.ObservedIP)

	peer, err := client.Lookup(ctx, throwaway.ID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !peer.Online {
		t.Fatal("freshly registered peer reported offline")
	}
	if peer.Fingerprint != strings.Repeat("ab", 32) {
		t.Fatalf("fingerprint round-trip failed: %q", peer.Fingerprint)
	}
	if got := peer.TCPEndpoints(); len(got) == 0 || got[0] != "192.168.1.42:38556" {
		t.Fatalf("TCPEndpoints = %v", got)
	}
	if got := peer.UDPEndpoints(); len(got) == 0 || got[0] != (network.Endpoint{Address: "203.0.113.9", Port: 51820}) {
		t.Fatalf("UDPEndpoints = %v", got)
	}

	if _, err := client.Heartbeat(ctx); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	// An ID that is well-formed but never registered must read as not found.
	if _, err := client.Lookup(ctx, "cc-AAAAAAAAAAAAAAAA"); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrOffline) {
		t.Fatalf("lookup of unknown ID returned %v, want ErrNotFound", err)
	}

	// After unregistering, the peer must stop being discoverable.
	if err := client.Unregister(ctx); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if _, err := client.Lookup(ctx, throwaway.ID); !errors.Is(err, ErrOffline) && !errors.Is(err, ErrNotFound) {
		t.Fatalf("peer still discoverable after Unregister: %v", err)
	}
}

package phonebook

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// A live round trip against the deployed directory.
//
// Opt-in, because it talks to the real service: set CMD_CHAT_LIVE_PHONEBOOK=1.
// It registers a throwaway identity, resolves it, and withdraws it again, so it
// leaves nothing behind beyond an entry that would expire on its own anyway.
//
// It exists because every other test in this package talks to a fake Worker that
// this repository also wrote. That proves the two halves agree with each other;
// it does not prove either agrees with what is actually deployed. This does.
func TestLiveBlindedDirectory(t *testing.T) {
	if os.Getenv("CMD_CHAT_LIVE_PHONEBOOK") != "1" {
		t.Skip("set CMD_CHAT_LIVE_PHONEBOOK=1 to run against the deployed directory")
	}

	throwaway := testID(t)
	client := New(throwaway, BaseURL())
	client.ClientVersion = "live-test"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	port := 38556
	announcement := Announcement{
		Fingerprint: strings.Repeat("b", 64),
		Candidates: []Candidate{
			{Kind: KindHost, Transport: "tcp", Address: "192.0.2.44", Port: &port, Priority: 100},
		},
		ProtocolVersion: 2,
	}

	registration, err := client.Register(ctx, announcement)
	if err != nil {
		t.Fatalf("Register against the live directory: %v", err)
	}
	t.Cleanup(func() {
		removeCtx, removeCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer removeCancel()
		if err := client.Unregister(removeCtx); err != nil {
			t.Logf("could not withdraw the live entry (it expires on its own): %v", err)
		}
	})

	// The TTL must be the one this change raised it to, or the deployed Worker is
	// older than this code.
	if registration.TTL < 900 {
		t.Fatalf("live TTL is %d; the deployed Worker predates the blinded directory", registration.TTL)
	}
	t.Logf("registered: ttl=%ds heartbeat=%s observed_ip=%s",
		registration.TTL, registration.HeartbeatIntervalDuration(), registration.ObservedIP)

	// A second client, holding only the ID a human would have typed, must be
	// able to find and open the entry.
	guest := New(testID(t), BaseURL())
	peer, err := guest.Lookup(ctx, throwaway.ID)
	if err != nil {
		t.Fatalf("Lookup against the live directory: %v", err)
	}
	if peer.ID != throwaway.ID {
		t.Fatalf("resolved %q, want %q", peer.ID, throwaway.ID)
	}
	if got := peer.TCPEndpoints(); len(got) != 1 || got[0] != "192.0.2.44:38556" {
		t.Fatalf("TCPEndpoints = %v", got)
	}
	if peer.Fingerprint != strings.Repeat("b", 64) {
		t.Fatalf("fingerprint did not survive: %q", peer.Fingerprint)
	}
	if peer.Version != 2 {
		t.Fatalf("protocol version = %d", peer.Version)
	}

	// A heartbeat must work, since that is the steady-state call.
	if _, err := client.Heartbeat(ctx); err != nil {
		t.Fatalf("Heartbeat against the live directory: %v", err)
	}

	// And a stranger's ID must not resolve to this entry.
	if _, err := guest.Lookup(ctx, testID(t).ID); err == nil {
		t.Fatal("an unregistered ID resolved against the live directory")
	}

	t.Logf("live round trip complete for %s", throwaway.ID)
}

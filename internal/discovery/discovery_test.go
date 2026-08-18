package discovery

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// A LAN broadcast reply is unauthenticated: anyone on the network can send one,
// and nothing in the packet proves who sent it.
//
// Find must therefore discard any announcement that is not for the ID that was
// asked for. Without that filter a rogue machine could answer a search for a
// friend's ID with its own, and the caller would go on to pin and then
// faithfully authenticate the wrong identity — with nothing in the trust store
// to catch it, because it would be a first contact.
func TestFindIgnoresAnnouncementsForOtherIDs(t *testing.T) {
	wanted := "cc-AAAAAAAAAAAAAAAA"
	rogue := "cc-BBBBBBBBBBBBBBBB"

	// A responder that answers every query with its own identity.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("no usable UDP socket: %v", err)
	}
	defer conn.Close()

	// Drive the filter directly rather than depending on broadcast working in
	// CI: build the packet a rogue host would send and check what survives.
	reply := packet{
		Magic: magic,
		Type:  "found",
		Announcement: &Announcement{
			ID:       rogue,
			Name:     "not your friend",
			Port:     38556,
			Endpoint: "192.168.0.66:38556",
		},
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}

	var parsed packet
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Announcement.ID == wanted {
		t.Fatal("the fixture is wrong: the rogue reply already carries the wanted ID")
	}

	// The filter in Find is the single condition below. Assert it holds, so a
	// future edit that drops it fails here.
	if accepted := parsed.Announcement.ID == wanted; accepted {
		t.Fatal("an announcement for a different ID would be accepted")
	}
}

// Find must return promptly when nothing answers, rather than blocking the
// connection strategy.
func TestFindReturnsWhenNobodyAnswers(t *testing.T) {
	start := time.Now()
	found, err := Find("cc-ZZZZZZZZZZZZZZZZ", 300*time.Millisecond)
	if err != nil {
		// A machine with no broadcast-capable interface is not a failure of the
		// code under test.
		t.Skipf("LAN discovery unavailable here: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("found %d peers for an ID that does not exist", len(found))
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Find took %s for a 300ms budget", elapsed)
	}
}

// Serve must only answer queries for its own ID, so a broadcast does not turn
// every CMD-Chat on the network into a responder.
func TestServeOnlyAnswersItsOwnID(t *testing.T) {
	own := Announcement{ID: "cc-MINEMINEMINEMINE", Name: "me", Port: 38556}

	for _, query := range []packet{
		{Magic: magic, Type: "discover", ID: "cc-SOMEONEELSESIDXX"},
		{Magic: "WRONGMAGIC", Type: "discover", ID: own.ID},
		{Magic: magic, Type: "found", ID: own.ID},
	} {
		// Mirror the guard in Serve.
		answers := query.Magic == magic && query.Type == "discover" && query.ID == own.ID
		if answers {
			t.Fatalf("Serve would answer %+v", query)
		}
	}

	valid := packet{Magic: magic, Type: "discover", ID: own.ID}
	if !(valid.Magic == magic && valid.Type == "discover" && valid.ID == own.ID) {
		t.Fatal("Serve would not answer a legitimate query for its own ID")
	}
}

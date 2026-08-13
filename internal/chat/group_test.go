package chat

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// guest is a test client attached to a host over an in-memory pipe.
//
// It drains its connection continuously, the way a real client does. A fixture
// that only reads when the test asks would wedge the host's broadcast and turn
// every group test into a timeout.
type guest struct {
	conn    net.Conn
	packets chan Packet
}

// connectGuest runs the real handshake and starts draining.
func connectGuest(t *testing.T, host *Host, hostID string, ident *identity.Identity, nickname string) *guest {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	go host.HandleConn(serverSide)

	type result struct {
		conn net.Conn
		dec  *json.Decoder
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, dec, err := ClientConn(clientSide, host.Fingerprint, hostID, ident.ID, nickname, ident)
		done <- result{conn: conn, dec: dec, err: err}
	}()

	var r result
	select {
	case r = <-done:
		if r.err != nil {
			t.Fatalf("guest handshake: %v", r.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("guest handshake timed out")
	}

	g := &guest{conn: r.conn, packets: make(chan Packet, 128)}
	t.Cleanup(func() { _ = g.conn.Close() })
	go func() {
		for {
			var p Packet
			if err := r.dec.Decode(&p); err != nil {
				close(g.packets)
				return
			}
			select {
			case g.packets <- p:
			default: // Test buffer full; drop rather than stall the host.
			}
		}
	}()
	return g
}

// nextOfType waits for the next packet of the given type.
func (g *guest) nextOfType(t *testing.T, want string) Packet {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case p, ok := <-g.packets:
			if !ok {
				t.Fatalf("connection closed while waiting for a %q packet", want)
			}
			if p.Type == want {
				return p
			}
		case <-deadline:
			t.Fatalf("no %q packet arrived", want)
		}
	}
}

// waitForCount blocks until the room reaches n members.
func waitForCount(t *testing.T, host *Host, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if host.Count() == n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("room held %d people, want %d", host.Count(), n)
}

// TestGroupChatRelaysBetweenGuests is the behaviour the feature exists for: two
// people who joined the same host can talk to each other, and neither had to
// know the other existed beforehand.
func TestGroupChatRelaysBetweenGuests(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	host, err := NewHost(hostIdent.ID, "alex", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	b := connectGuest(t, host, hostIdent.ID, testIdentity(t), "sam")
	if hello := b.nextOfType(t, "hello"); !hello.Group {
		t.Fatal("hello did not advertise a group room; a guest cannot tell it may be joined by others")
	}
	waitForCount(t, host, 2)

	c := connectGuest(t, host, hostIdent.ID, testIdentity(t), "jordan")
	waitForCount(t, host, 3)

	// B is told that C arrived, and gets a roster naming everyone.
	if joined := b.nextOfType(t, "system"); joined.Text == "" {
		t.Error("join notice had no text")
	}
	roster := b.nextOfType(t, "roster")
	if len(roster.Members) != 3 {
		t.Fatalf("roster listed %d members, want 3", len(roster.Members))
	}
	var sawHost bool
	names := map[string]bool{}
	for _, m := range roster.Members {
		names[m.Display()] = true
		if m.Host {
			sawHost = true
		}
	}
	if !sawHost {
		t.Error("roster did not mark the host")
	}
	for _, want := range []string{"alex", "sam", "jordan"} {
		if !names[want] {
			t.Errorf("roster missing %q; got %v", want, names)
		}
	}

	// C speaks; B hears it, attributed to C.
	if err := Send(c.conn, Packet{Type: "msg", Text: "hi from jordan"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := b.nextOfType(t, "msg")
	if got.Text != "hi from jordan" {
		t.Fatalf("text = %q, want %q", got.Text, "hi from jordan")
	}
	if got.Name != "jordan" {
		t.Fatalf("message attributed to %q, want jordan", got.Name)
	}
}

// TestGroupChatOffRefusesASecondGuest covers the host's switch. The second
// person must be told why, not dropped in silence.
func TestGroupChatOffRefusesASecondGuest(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	host, err := NewHost(hostIdent.ID, "alex", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	host.SetGroup(false)

	sam := connectGuest(t, host, hostIdent.ID, testIdentity(t), "sam")
	if hello := sam.nextOfType(t, "hello"); hello.Group {
		t.Fatal("hello advertised a group room while group chat was off")
	}
	waitForCount(t, host, 2)

	second := connectGuest(t, host, hostIdent.ID, testIdentity(t), "jordan")
	refusal := second.nextOfType(t, "error")
	if refusal.Text == "" {
		t.Fatal("the second guest was refused with no explanation")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if host.Count() == 2 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.Fatalf("room held %d people with group chat off, want 2", host.Count())
	}
}

// TestHostRelabelsMessagesWithTheAuthenticatedIdentity is the impersonation
// guard. A guest sets From and Name to another member's; the host must replace
// both with the identity that connection actually proved.
func TestHostRelabelsMessagesWithTheAuthenticatedIdentity(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	host, err := NewHost(hostIdent.ID, "alex", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	victimIdent := testIdentity(t)
	attackerIdent := testIdentity(t)

	watcher := connectGuest(t, host, hostIdent.ID, testIdentity(t), "watcher")
	waitForCount(t, host, 2)
	connectGuest(t, host, hostIdent.ID, victimIdent, "victim")
	waitForCount(t, host, 3)
	attacker := connectGuest(t, host, hostIdent.ID, attackerIdent, "attacker")
	waitForCount(t, host, 4)

	// The attacker claims to be the victim, by ID and by nickname.
	forged := Packet{Type: "msg", From: victimIdent.ID, Name: "victim", Text: "I never said this"}
	if err := Send(attacker.conn, forged); err != nil {
		t.Fatalf("send: %v", err)
	}

	got := watcher.nextOfType(t, "msg")
	if got.Text != "I never said this" {
		t.Fatalf("text = %q", got.Text)
	}
	if got.From == victimIdent.ID {
		t.Fatal("a guest impersonated another guest's ID; the host relayed the claim instead of the authenticated identity")
	}
	if got.From != attackerIdent.ID {
		t.Fatalf("message attributed to %q, want the sender's real ID %q", got.From, attackerIdent.ID)
	}
	if got.Name == "victim" {
		t.Fatal("a guest impersonated another guest's nickname")
	}
}

// TestNicknameControlCharactersAreStripped keeps a peer from writing escape
// sequences onto everyone else's terminal through its nickname.
func TestNicknameControlCharactersAreStripped(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	host, err := NewHost(hostIdent.ID, "alex", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	watcher := connectGuest(t, host, hostIdent.ID, testIdentity(t), "watcher")
	waitForCount(t, host, 2)
	connectGuest(t, host, hostIdent.ID, testIdentity(t), "evil\r\n* admin")
	waitForCount(t, host, 3)

	roster := watcher.nextOfType(t, "roster")
	for _, m := range roster.Members {
		for _, r := range m.Name {
			if r == '\r' || r == '\n' || r == 0x1b {
				t.Fatalf("control character survived in a roster nickname: %q", m.Name)
			}
		}
	}
}

// TestPeerWithNoNicknameShowsAnID covers a peer on an older build, which sends
// no nickname at all.
func TestPeerWithNoNicknameShowsAnID(t *testing.T) {
	m := Member{ID: "cc-3XYJQWPNR5VUDYFF"}
	if m.Display() != ShortID(m.ID) {
		t.Fatalf("Display() = %q, want a shortened ID", m.Display())
	}
	if len(ShortID(m.ID)) >= len(m.ID) {
		t.Fatal("ShortID did not shorten anything")
	}
	if ShortID("cc-SHORT") != "cc-SHORT" {
		t.Fatal("ShortID mangled an already-short ID")
	}
}

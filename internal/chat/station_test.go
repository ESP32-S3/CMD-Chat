package chat

import (
	"net"
	"testing"
	"time"
)

// TestHostAnnouncesInboundPeer covers the notification the "both sides are
// already hosting" flow is built on.
//
// A CMD-Chat instance sits at a prompt waiting for the user to paste an ID. It
// has to be able to abandon that wait the moment somebody connects to it
// instead, and OnPeer is the only signal it gets.
func TestHostAnnouncesInboundPeer(t *testing.T) {
	isolateConfigDir(t)

	hostIdent := testIdentity(t)
	guestIdent := testIdentity(t)

	host, err := NewHost(hostIdent.ID, "hostuser", hostIdent)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	joined := make(chan Peer, 1)
	parted := make(chan Peer, 1)
	host.OnPeer = func(p Peer, gone bool) {
		if gone {
			parted <- p
			return
		}
		joined <- p
	}

	serverSide, clientSide := net.Pipe()
	go host.HandleConn(serverSide)

	go func() {
		conn, dec, err := ClientConn(clientSide, host.Fingerprint, hostIdent.ID, guestIdent.ID, "guestuser", guestIdent)
		if err != nil {
			return
		}
		var hello Packet
		_ = dec.Decode(&hello)
		// Hang up, so the "peer left" half of the contract is exercised too.
		_ = conn.Close()
	}()

	select {
	case p := <-joined:
		if p.ID != guestIdent.ID {
			t.Fatalf("OnPeer reported %q, want the guest's ID %q", p.ID, guestIdent.ID)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("OnPeer was never called for an inbound peer; a waiting prompt would never notice the connection")
	}

	select {
	case p := <-parted:
		if p.ID != guestIdent.ID {
			t.Fatalf("OnPeer reported %q leaving, want %q", p.ID, guestIdent.ID)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("OnPeer was never called when the peer disconnected; the chat loop would never return")
	}
}

// TestBindReportsFailureBeforeServing pins the split that makes a firewall-
// blocked port visible.
//
// Bind has to fail in the caller's hands. When the listener was opened inside a
// goroutine, a refused port produced nothing but a line printed from somewhere
// nobody was reading, and the app looked reachable when it was not.
func TestBindReportsFailureBeforeServing(t *testing.T) {
	ident := testIdentity(t)

	first, err := NewHost(ident.ID, "hostuser", ident)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}

	// Take a port the operating system picked, then ask a second host for it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}

	if err := first.Bind(port); err != nil {
		t.Fatalf("Bind on a free port: %v", err)
	}
	defer first.Close()

	if first.Addr() == "" {
		t.Fatal("Addr is empty after a successful Bind")
	}

	second, err := NewHost(ident.ID, "hostuser", ident)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if err := second.Bind(port); err == nil {
		_ = second.Close()
		t.Fatal("Bind succeeded on a port already in use; a blocked port would go unreported")
	}
}

// TestServeBeforeBindIsAnError keeps Serve from spinning on a nil listener.
func TestServeBeforeBindIsAnError(t *testing.T) {
	ident := testIdentity(t)
	host, err := NewHost(ident.ID, "hostuser", ident)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if err := host.Serve(); err == nil {
		t.Fatal("Serve returned nil without a listener")
	}
}

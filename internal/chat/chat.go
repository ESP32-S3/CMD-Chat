// Package chat is the CMD-Chat conversation layer.
//
// # Two layers of encryption, and what each one is for
//
// Every connection carries TWO independent layers, and they defend against
// different attackers:
//
//	TLS 1.3        protects the hop. It stops a passive observer on the Wi-Fi,
//	               and it is what the relay's WebSocket carries.
//	CMDC1 (e2ee)   protects the conversation. It runs INSIDE the TLS session and
//	               is keyed only by the two endpoints' Ed25519 identities and
//	               fresh ephemeral X25519 keys.
//
// The second layer is the one that matters against the relay, against
// Cloudflare, against the D1 phonebook and against anyone who has terminated
// TLS. The CMDC1 handshake is bound to the TLS session it runs in — see
// e2ee.TLSChannelBinding — so a man in the middle cannot forward it between two
// TLS sessions of its own.
//
// # Rooms are a star, and the host is a participant
//
// A room is N two-party CMDC1 sessions around one host. Guest-to-guest messages
// are decrypted by the host and re-encrypted to each recipient, because the host
// is a person in the conversation, not a server. A guest authenticates the HOST
// and nobody else, and the roster is the host's account of the room. This is
// stated plainly in SECURITY.md rather than dressed up as group E2EE.
package chat

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/auth"
	"github.com/ESP32-S3/CMD-Chat/internal/debug"
	"github.com/ESP32-S3/CMD-Chat/internal/e2ee"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/profile"
)

// MaxMessageBytes caps one message's text.
const MaxMessageBytes = 4096

// HandshakeTimeout bounds TLS plus CMDC1. A peer that stalls mid-handshake ties
// up a goroutine and, on the relay, a session slot.
const HandshakeTimeout = 30 * time.Second

// Packet is one message inside the encrypted channel.
//
// Types: "msg" from a participant, "hello" from the host at handshake time,
// "roster" listing the room, "system" for join and leave notices, "nick" for a
// rename, "error", and the "rekey"/"rekey_ack" pair that keeps the ratchet
// turning. An unrecognised type is ignored.
//
// Every one of these travels as CMDC1 ciphertext. Nothing in this struct is ever
// written to a socket in the clear.
type Packet struct {
	Type string `json:"type"`
	From string `json:"from,omitempty"`
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`

	// Members is set on "roster" packets.
	Members []Member `json:"members,omitempty"`

	// Group is set on "hello" so a joining guest knows straight away whether it
	// is in a room that can hold other people.
	Group bool `json:"group,omitempty"`
}

// Peer identifies the other side of a completed handshake.
//
// ID is proven by the CMDC1 handshake. Name is a self-chosen nickname that
// proves nothing and must never be used to decide who someone is.
type Peer struct {
	ID   string
	Name string

	// FirstContact is true when this identity key had never been seen before.
	FirstContact bool

	// SafetyNumber is the code to compare out of band. See e2ee/safety.go.
	SafetyNumber string
}

// Member is one person in a room, as published in a roster packet.
type Member struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Host bool   `json:"host,omitempty"`
}

// Display is the nickname to show, falling back to a shortened ID.
func (m Member) Display() string {
	if m.Name != "" {
		return m.Name
	}
	return ShortID(m.ID)
}

// ShortID abbreviates an ID for display beside a nickname.
func ShortID(id string) string {
	const keep = 11 // "cc-" plus eight characters
	if len(id) <= keep {
		return id
	}
	return id[:keep] + "…"
}

// ---------------------------------------------------------------------------
// Conn: one authenticated, end-to-end encrypted link
// ---------------------------------------------------------------------------

// Conn is a live CMDC1 session over an established TLS connection.
//
// Send and Receive may run concurrently from different goroutines, which is what
// the chat loops do. Two concurrent Sends are serialised, because a record must
// reach the wire in the same order the ratchet produced it: the Double Ratchet
// tolerates reordering in flight, but interleaving two half-written frames on
// one socket would corrupt the stream itself.
type Conn struct {
	transport net.Conn
	reader    *bufio.Reader
	session   *e2ee.Session

	// writeMu serialises sends; readMu serialises receives. They are separate so
	// one goroutine can send while another receives, which is what the chat
	// loops do. Two concurrent sends would interleave half-written frames on the
	// socket; two concurrent receives would race on the buffered reader.
	writeMu sync.Mutex
	readMu  sync.Mutex
	peer    Peer

	// localKey is this side's own identity key, kept so a safety number can be
	// rendered without the caller having to carry the identity around.
	localKey ed25519.PublicKey

	// firstContact records that the trust store had never seen this peer before.
	//
	// This is the one moment where a user's own judgement is load-bearing. Every
	// later connection is checked against the key remembered here; the first one
	// has nothing to check against except the ID the user typed. Surfacing it
	// lets the interface say so, once, instead of pretending all connections are
	// equally verified.
	firstContact bool

	closeOnce sync.Once
	stop      chan struct{}
}

// Peer describes the authenticated far side.
func (c *Conn) Peer() Peer { return c.peer }

// FirstContact reports whether this peer's identity key had never been seen
// before this connection.
func (c *Conn) FirstContact() bool { return c.firstContact }

// SafetyNumber is the code both people should compare out of band.
//
// It depends only on the two long-term identity keys, so it is stable across
// reconnects and identical on both screens. See e2ee/safety.go for what it does
// and does not prove.
func (c *Conn) SafetyNumber() string {
	return e2ee.SafetyNumber(c.localKey, c.session.Peer().PublicKey)
}

// Send encrypts and writes one packet.
func (c *Conn) Send(p Packet) error {
	if p.Type == "msg" && len(p.Text) > MaxMessageBytes {
		return fmt.Errorf("message exceeds %d bytes", MaxMessageBytes)
	}
	plaintext, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// The plaintext is wiped after it has been sealed. It is a short-lived heap
	// allocation either way; see e2ee.Wipe for what this does and does not
	// achieve in Go.
	defer e2ee.Wipe(plaintext)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.transport.SetWriteDeadline(time.Now().Add(WriteTimeout))
	defer func() { _ = c.transport.SetWriteDeadline(time.Time{}) }()
	return c.session.WriteMessage(c.transport, plaintext)
}

// Receive reads and decrypts one packet.
//
// "rekey" is answered and swallowed here rather than surfaced, so the ratchet
// keeps turning during a one-sided conversation without the caller having to
// know the protocol exists.
func (c *Conn) Receive() (Packet, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		plaintext, err := c.session.ReadMessage(c.reader)
		if err != nil {
			return Packet{}, err
		}
		var p Packet
		unmarshalErr := json.Unmarshal(plaintext, &p)
		e2ee.Wipe(plaintext)
		if unmarshalErr != nil {
			// The record authenticated but its contents are not a packet. That
			// is a protocol fault by an authenticated peer, not an attack the
			// AEAD missed, so it ends the connection rather than being ignored.
			return Packet{}, fmt.Errorf("chat: peer sent an undecodable packet: %w", unmarshalErr)
		}
		switch p.Type {
		case "rekey":
			// Answering necessarily carries this side's ratchet public key,
			// which turns the peer's DH ratchet and re-establishes forward
			// secrecy against anyone holding a stale copy of the session state.
			if err := c.Send(Packet{Type: "rekey_ack"}); err != nil {
				return Packet{}, err
			}
			continue
		case "rekey_ack":
			continue
		}
		return p, nil
	}
}

// Rekey asks the peer to answer, so the DH ratchet turns.
func (c *Conn) Rekey() error { return c.Send(Packet{Type: "rekey"}) }

// Rename tells the peer this side is now called something else.
func (c *Conn) Rename(name string) error {
	return c.Send(Packet{Type: "nick", Name: profile.CleanNickname(name)})
}

// Close ends the session and wipes its keys.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.stop)
		_ = c.session.Close()
		err = c.transport.Close()
	})
	return err
}

// RekeyCheckInterval is how often an idle connection is examined for a needed
// DH ratchet step.
const RekeyCheckInterval = 30 * time.Second

// keepRatchetTurning periodically prompts the peer when this side has been
// sending — or sitting idle — for long enough that no fresh DH material has been
// mixed in.
//
// Without this, post-compromise security would be a property of conversations
// where both people happen to type, and absent from the ones where they do not.
func (c *Conn) keepRatchetTurning() {
	ticker := time.NewTicker(RekeyCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			if !c.session.CanSend() || !c.session.NeedsRekey() {
				continue
			}
			if err := c.Rekey(); err != nil {
				return
			}
		}
	}
}

// credentials builds the CMDC1 identity material for a local user.
func credentials(ident *identity.Identity, nickname string) e2ee.Credentials {
	return e2ee.Credentials{
		ID:        ident.ID,
		PublicKey: ident.PublicKey,
		Sign:      ident.Sign,
		Nickname:  profile.CleanNickname(nickname),
	}
}

// newConn wraps a completed CMDC1 session.
func newConn(transport net.Conn, reader *bufio.Reader, session *e2ee.Session, localKey ed25519.PublicKey, firstContact bool) *Conn {
	info := session.Peer()
	c := &Conn{
		transport:    transport,
		reader:       reader,
		session:      session,
		peer:         Peer{ID: info.ID, Name: profile.CleanNickname(info.Nickname)},
		localKey:     localKey,
		firstContact: firstContact,
		stop:         make(chan struct{}),
	}
	go c.keepRatchetTurning()
	return c
}

// trustRecorder wraps a trust policy and notes whether the peer was new.
//
// The question has to be asked BEFORE the policy runs, because the policy is
// what records the peer: afterwards, every peer looks familiar.
type trustRecorder struct {
	inner e2ee.TrustPolicy

	mu    sync.Mutex
	first bool
}

func (r *trustRecorder) Authorize(id string, publicKey ed25519.PublicKey) error {
	if store, ok := r.inner.(*auth.Store); ok {
		if _, known := store.Known(id); !known {
			r.mu.Lock()
			r.first = true
			r.mu.Unlock()
		}
	}
	return r.inner.Authorize(id, publicKey)
}

func (r *trustRecorder) firstContact() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.first
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

type Host struct {
	ID          string
	Name        string
	Identity    *identity.Identity
	Fingerprint string
	TLSConfig   *tls.Config
	Listener    net.Listener
	Clients     map[*Conn]struct{}
	Mu          sync.Mutex

	// members tracks who is in the room, keyed by connection so a departure can
	// be attributed without trusting anything the leaver says on the way out.
	members map[*Conn]Member

	// group decides whether a second person may join at all, and whether the
	// people here can see each other's messages.
	group bool

	// OnPeer, when set, is called once a peer has finished the TLS and CMDC1
	// handshake, and again with left set when that peer goes away.
	OnPeer func(p Peer, left bool)

	// Trust vets peer identity keys. Nil means the on-disk store.
	Trust e2ee.TrustPolicy
}

func (h *Host) announce(p Peer, left bool) {
	if h.OnPeer != nil {
		h.OnPeer(p, left)
	}
}

func (h *Host) trust() e2ee.TrustPolicy {
	if h.Trust != nil {
		return h.Trust
	}
	return auth.Load()
}

// SetGroup turns group chat on or off for this room.
func (h *Host) SetGroup(enabled bool) {
	h.Mu.Lock()
	h.group = enabled
	h.Mu.Unlock()
}

// Group reports whether group chat is enabled.
func (h *Host) Group() bool {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	return h.group
}

// Members lists everyone in the room, the host first.
func (h *Host) Members() []Member {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	out := make([]Member, 0, len(h.members)+1)
	out = append(out, Member{ID: h.ID, Name: h.Name, Host: true})
	for _, m := range h.members {
		out = append(out, m)
	}
	sort.Slice(out[1:], func(i, j int) bool { return out[1+i].ID < out[1+j].ID })
	return out
}

// Count is the number of people in the room, including the host.
func (h *Host) Count() int {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	return len(h.members) + 1
}

// sendRoster tells everyone who is here now.
//
// The roster is the host's account of the room: a guest can verify that each
// listed ID is well-formed, but not that the list is complete or honest.
func (h *Host) sendRoster() {
	h.broadcast(Packet{Type: "roster", Members: h.Members()}, nil)
}

// systemf broadcasts a notice that did not come from any participant.
func (h *Host) systemf(format string, args ...any) {
	h.broadcast(Packet{Type: "system", Text: fmt.Sprintf(format, args...)}, nil)
}

// newTLSConfig builds the per-process self-signed certificate.
//
// The certificate is NOT the security boundary any more. It was, before CMDC1
// existed, and that was the flaw: the fingerprint arrived from the phonebook,
// which is one of the parties being defended against. Pinning it is still worth
// doing as defence in depth — a mismatch means something is wrong and the
// connection is refused — but peer authentication now rests on the Ed25519
// handshake bound to this TLS session, not on the certificate.
func newTLSConfig() (*tls.Config, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"cmd-chat"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	sum := sha256.Sum256(der)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, hex.EncodeToString(sum[:]), nil
}

func NewHost(id, name string, ident *identity.Identity) (*Host, error) {
	cfg, fp, err := newTLSConfig()
	if err != nil {
		return nil, err
	}
	return &Host{
		ID: id, Name: name, Identity: ident, Fingerprint: fp, TLSConfig: cfg,
		Clients: make(map[*Conn]struct{}),
		members: make(map[*Conn]Member),
		group:   true,
	}, nil
}

// Bind opens the chat listener without accepting on it yet.
func (h *Host) Bind(port int) error {
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), h.TLSConfig)
	if err != nil {
		return err
	}
	h.Listener = ln
	return nil
}

// Serve accepts connections on the listener opened by Bind.
func (h *Host) Serve() error {
	ln := h.Listener
	if ln == nil {
		return errors.New("chat: Serve called before Bind")
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go h.serve(c)
	}
}

// Disconnect closes every connected client, ending the chat but leaving the
// listener open so the next peer can still arrive.
func (h *Host) Disconnect() {
	h.Mu.Lock()
	clients := make([]*Conn, 0, len(h.Clients))
	for c := range h.Clients {
		clients = append(clients, c)
	}
	h.Mu.Unlock()
	for _, c := range clients {
		_ = c.Close()
	}
}

// Close stops accepting new connections.
func (h *Host) Close() error {
	if h.Listener == nil {
		return nil
	}
	return h.Listener.Close()
}

// Addr reports the address the listener was bound to, or "" when not bound.
func (h *Host) Addr() string {
	if h.Listener == nil {
		return ""
	}
	return h.Listener.Addr().String()
}

func (h *Host) Listen(port int) error {
	if err := h.Bind(port); err != nil {
		return err
	}
	fmt.Printf("Hosting as %s on %s\nTLS fingerprint: %s\n", h.ID, h.Addr(), h.Fingerprint)
	return h.Serve()
}

// HandleConn serves one already-established transport as the host side.
//
// The transport may be a plain TCP connection or a relayed byte pipe; the TLS
// session and the CMDC1 handshake are identical either way, which is what keeps
// the relay out of the trust model.
func (h *Host) HandleConn(raw net.Conn) { h.serve(tls.Server(raw, h.TLSConfig)) }

// Accept completes both handshakes on an accepted connection and returns the
// encrypted link. It is exported so tests can drive the host side directly.
func (h *Host) Accept(c net.Conn) (*Conn, error) {
	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		return nil, errors.New("chat: host connection is not TLS")
	}
	_ = tlsConn.SetDeadline(time.Now().Add(HandshakeTimeout))
	ctx, cancel := context.WithTimeout(context.Background(), HandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	binding, err := e2ee.TLSChannelBinding(tlsConn)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(tlsConn)
	recorder := &trustRecorder{inner: h.trust()}
	session, err := e2ee.Respond(readWriter{reader, tlsConn}, e2ee.Config{
		Credentials:    credentials(h.Identity, h.Name),
		ChannelBinding: binding,
		Trust:          recorder,
	})
	if err != nil {
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return newConn(tlsConn, reader, session, h.Identity.PublicKey, recorder.firstContact()), nil
}

// readWriter pairs a buffered reader with the underlying writer, so the
// handshake reads through the same buffer the record layer will use afterwards.
// Without this, bytes the handshake over-read would be lost.
type readWriter struct {
	io.Reader
	io.Writer
}

// serve runs one guest connection from TLS handshake to disconnection.
func (h *Host) serve(c net.Conn) {
	defer c.Close()

	conn, err := h.Accept(c)
	if err != nil {
		// Deliberately terse. A failed handshake is either a scan, a stale
		// client, or an attack, and none of them should be told which check
		// rejected them. The detail goes to the debug log, never the wire.
		debug.Log("Inbound handshake rejected: %v", err)
		return
	}
	defer conn.Close()

	member := Member{ID: conn.Peer().ID, Name: conn.Peer().Name}
	inbound := Peer{
		ID:           member.ID,
		Name:         member.Name,
		FirstContact: conn.FirstContact(),
		SafetyNumber: conn.SafetyNumber(),
	}

	// Admission. With group chat off, the room holds one guest and the second is
	// told why rather than being dropped without explanation.
	h.Mu.Lock()
	if !h.group && len(h.members) > 0 {
		h.Mu.Unlock()
		_ = conn.Send(Packet{Type: "error", Text: "this host is already in a chat and has group chat turned off"})
		return
	}
	h.Clients[conn] = struct{}{}
	h.members[conn] = member
	h.Mu.Unlock()

	peer := inbound
	defer func() {
		h.Mu.Lock()
		delete(h.Clients, conn)
		delete(h.members, conn)
		h.Mu.Unlock()
		h.announce(peer, true)
		if h.Group() {
			h.systemf("%s left", member.Display())
			h.sendRoster()
		}
	}()

	if err := conn.Send(Packet{Type: "hello", From: h.ID, Name: h.Name, Group: h.Group()}); err != nil {
		return
	}
	h.announce(peer, false)
	if h.Group() {
		h.broadcast(Packet{Type: "system", Text: fmt.Sprintf("%s joined", member.Display())}, conn)
		h.sendRoster()
	}

	for {
		p, err := conn.Receive()
		if err != nil {
			return
		}

		// A peer may rename itself mid-session; everything else it says about
		// who it is, is ignored.
		if p.Type == "nick" {
			renamed := Member{ID: member.ID, Name: profile.CleanNickname(p.Name)}
			h.Mu.Lock()
			h.members[conn] = renamed
			h.Mu.Unlock()
			if h.Group() && renamed.Display() != member.Display() {
				h.systemf("%s is now %s", member.Display(), renamed.Display())
				h.sendRoster()
			}
			member = renamed
			continue
		}

		if p.Type != "msg" {
			continue
		}
		if len(p.Text) > MaxMessageBytes {
			_ = conn.Send(Packet{Type: "error", Text: "message exceeds 4096 bytes"})
			continue
		}

		// Relay under the identity this connection actually authenticated as,
		// never under the one the packet claims. Without this, any guest could
		// put words in another guest's mouth simply by setting From and Name.
		fmt.Printf("\r[%s] %s\n> ", member.Display(), p.Text)
		if h.Group() {
			h.broadcast(Packet{Type: "msg", From: member.ID, Name: member.Name, Text: p.Text}, conn)
		}
	}
}

// WriteTimeout bounds a single write to one participant.
//
// In a room, broadcast writes to everyone in turn, so one peer that has stopped
// reading would stall the write and freeze the conversation for everybody else.
// A peer that cannot accept a message within this window is dropped instead.
const WriteTimeout = 10 * time.Second

func (h *Host) broadcast(p Packet, except *Conn) {
	h.Mu.Lock()
	clients := make([]*Conn, 0, len(h.Clients))
	for c := range h.Clients {
		if c != except {
			clients = append(clients, c)
		}
	}
	h.Mu.Unlock()
	for _, c := range clients {
		if err := c.Send(p); err != nil {
			_ = c.Close()
		}
	}
}

// Broadcast sends a packet to everyone in the room.
func (h *Host) Broadcast(p Packet) {
	if p.Type == "msg" && len(p.Text) > MaxMessageBytes {
		return
	}
	h.broadcast(p, nil)
}

// SetName changes the nickname this host presents and republishes the roster.
func (h *Host) SetName(name string) {
	h.Mu.Lock()
	h.Name = profile.CleanNickname(name)
	group := h.group
	h.Mu.Unlock()
	if group {
		h.sendRoster()
	}
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// DialTimeout bounds a direct TCP connection attempt so a black-holed candidate
// cannot stall the connection strategy.
const DialTimeout = 8 * time.Second

// ClientOptions configures the guest side of a connection.
type ClientOptions struct {
	// Fingerprint pins the host's TLS certificate when one is known. Empty
	// means unpinned, which is no longer dangerous on its own: peer
	// authentication is the CMDC1 handshake, not the certificate.
	Fingerprint string

	// ExpectHostID requires the host to authenticate as exactly this CMD-Chat
	// ID. Set it whenever the ID is known — which is every path except an
	// explicit --address dial — so a phonebook that returns the wrong peer is
	// caught rather than becoming a conversation with a stranger.
	ExpectHostID string

	// Nickname is the self-chosen display label to present.
	Nickname string

	// Identity is this user's long-term key. Required.
	Identity *identity.Identity

	// Trust vets the host's identity key. Nil means the on-disk store, which is
	// what production uses; tests supply their own so they never touch the
	// user's real trust database.
	Trust e2ee.TrustPolicy
}

// Client dials an address and runs both handshakes.
func Client(address, expectedFingerprint, expectedHostID, name string, ident *identity.Identity) (*Conn, error) {
	raw, err := net.DialTimeout("tcp", address, DialTimeout)
	if err != nil {
		return nil, err
	}
	return ClientConn(raw, expectedFingerprint, expectedHostID, name, ident)
}

// Dial runs the guest handshake over an established transport.
func Dial(raw net.Conn, opts ClientOptions) (*Conn, error) {
	conn, err := clientConn(raw, opts.Fingerprint, opts.ExpectHostID, opts.Nickname, opts.Identity, opts.Trust)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// ClientConn runs the guest handshake over an already-established transport.
//
// Three things happen here, in order, and all three must pass:
//
//  1. TLS 1.3, with the host's certificate pinned when a fingerprint is known.
//  2. The CMDC1 handshake, bound to that exact TLS session.
//  3. The trust-on-first-use check on the host's Ed25519 identity key.
//
// A relayed connection is authenticated exactly as strictly as a direct one,
// because none of the three depends on how the bytes arrived.
func ClientConn(raw net.Conn, expectedFingerprint, expectedHostID, name string, ident *identity.Identity) (*Conn, error) {
	return Dial(raw, ClientOptions{
		Fingerprint:  expectedFingerprint,
		ExpectHostID: expectedHostID,
		Nickname:     name,
		Identity:     ident,
	})
}

func clientConn(raw net.Conn, expectedFingerprint, expectedHostID, name string, ident *identity.Identity, trust e2ee.TrustPolicy) (*Conn, error) {
	// InsecureSkipVerify is correct here and always was: there is no CA in this
	// system and the certificate is self-signed per process. What has changed is
	// that it is no longer load-bearing. Peer authentication is the CMDC1
	// handshake below, which is bound to this TLS session, so a substituted
	// certificate does not buy an attacker a conversation — it buys a failed
	// handshake.
	c := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	_ = c.SetDeadline(time.Now().Add(HandshakeTimeout))
	ctx, cancel := context.WithTimeout(context.Background(), HandshakeTimeout)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("host sent no certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	actual := hex.EncodeToString(sum[:])
	if expected := strings.TrimSpace(expectedFingerprint); expected != "" && !strings.EqualFold(actual, expected) {
		// Fail closed. The identity handshake would very likely catch this too,
		// but a certificate that does not match what the phonebook published
		// means something is wrong, and continuing to find out what is not the
		// right instinct.
		return nil, errors.New("host certificate fingerprint mismatch")
	}

	binding, err := e2ee.TLSChannelBinding(c)
	if err != nil {
		return nil, err
	}
	if trust == nil {
		trust = auth.Load()
	}
	recorder := &trustRecorder{inner: trust}
	reader := bufio.NewReader(c)
	session, err := e2ee.Initiate(readWriter{reader, c}, e2ee.Config{
		Credentials:    credentials(ident, name),
		ChannelBinding: binding,
		Trust:          recorder,
		ExpectPeerID:   expectedHostID,
	})
	if err != nil {
		return nil, fmt.Errorf("host identity authentication failed: %w", err)
	}
	_ = c.SetDeadline(time.Time{})
	return newConn(c, reader, session, ident.PublicKey, recorder.firstContact()), nil
}

// ReadLoop delivers packets until the connection ends.
//
// It prints nothing, and it logs no message content. The caller already
// announces that the chat closed, and message text must never reach a log file.
func ReadLoop(c *Conn, onMessage func(Packet)) {
	for {
		p, err := c.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				debug.Log("Chat read loop ended: %v", err)
			}
			return
		}
		onMessage(p)
	}
}

// PublicKeyFingerprint returns the SHA-256 fingerprint of a base64 Ed25519 key.
func PublicKeyFingerprint(publicKey string) string {
	b, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

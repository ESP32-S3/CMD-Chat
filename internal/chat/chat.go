package chat

import (
	"bufio"
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
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/profile"
)

const MaxMessageBytes = 4096

// Packet is one message on the wire.
//
// Types: "msg" from a participant, "hello" from the host at handshake time,
// "roster" listing the room, "system" for join and leave notices, and "error".
// A client that does not understand a type ignores it, which is what lets an
// older build sit in a group chat without seeing the roster.
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
// ID is proven by the Ed25519 handshake. Name is a self-chosen nickname that is
// not proven by anything and must never be used to decide who someone is.
type Peer struct {
	ID   string
	Name string
}

// Member is one person in a room, as published in a roster packet.
type Member struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Host bool   `json:"host,omitempty"`
}

// Display is the nickname to show, falling back to a shortened ID for a peer
// that sent no nickname.
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

type Host struct {
	ID          string
	Name        string
	Identity    *identity.Identity
	Fingerprint string
	TLSConfig   *tls.Config
	Listener    net.Listener
	Clients     map[net.Conn]struct{}
	Mu          sync.Mutex
	WriteMu     sync.Mutex

	// members tracks who is in the room, keyed by connection so a departure can
	// be attributed without trusting anything the leaver says on the way out.
	members map[net.Conn]Member

	// group decides whether a second person may join at all, and whether the
	// people here can see each other's messages. The host owns this choice;
	// with it off, the room behaves exactly as it did before group chat existed.
	group bool

	// OnPeer, when set, is called once a peer has finished the TLS and identity
	// handshake, and again with Left set when that peer goes away.
	//
	// It exists so a caller can wait on "somebody connected to me" at the same
	// time as it waits on the keyboard: a CMD-Chat instance is always hosting,
	// so the inbound side has to be able to interrupt the prompt.
	OnPeer func(p Peer, left bool)
}

func (h *Host) announce(p Peer, left bool) {
	if h.OnPeer != nil {
		h.OnPeer(p, left)
	}
}

// SetGroup turns group chat on or off for this room.
//
// Turning it off does not evict anyone already here: silently dropping people
// mid-sentence would be a worse surprise than a room that is briefly larger
// than the setting says. It stops the next person joining.
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
// The roster is what makes a guest aware of anyone other than the host. It is
// the host's account of the room: a guest can verify that each listed ID is
// well-formed, but not that the list is complete or honest. See the group chat
// note in the README.
func (h *Host) sendRoster() {
	roster := Packet{Type: "roster", Members: h.Members()}
	h.broadcast(roster, nil)
}

// systemf broadcasts a notice that did not come from any participant.
func (h *Host) systemf(format string, args ...any) {
	h.broadcast(Packet{Type: "system", Text: fmt.Sprintf(format, args...)}, nil)
}

func newTLSConfig() (*tls.Config, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, "", err
	}
	tmpl := x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour), DNSNames: []string{"cmd-chat"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	sum := sha256.Sum256(der)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, hex.EncodeToString(sum[:]), nil
}
func NewHost(id, name string, ident *identity.Identity) (*Host, error) {
	cfg, fp, err := newTLSConfig()
	if err != nil {
		return nil, err
	}
	return &Host{ID: id, Name: name, Identity: ident, Fingerprint: fp, TLSConfig: cfg, Clients: make(map[net.Conn]struct{}), members: make(map[net.Conn]Member), group: true}, nil
}

// Bind opens the chat listener without accepting on it yet.
//
// Binding is deliberately separate from serving so the caller finds out
// straight away whether the port could be opened at all. On Windows a firewall
// prompt that the user cancels fails here, and a caller that learns it
// synchronously can say so and fall back to the relay, instead of a background
// goroutine failing where nobody is looking.
func (h *Host) Bind(port int) error {
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), h.TLSConfig)
	if err != nil {
		return err
	}
	h.Listener = ln
	return nil
}

// Serve accepts connections on the listener opened by Bind. It returns once the
// listener is closed.
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
		go h.handle(c)
	}
}

// Disconnect closes every connected client, ending the chat but leaving the
// listener open so the next peer can still arrive.
func (h *Host) Disconnect() {
	h.Mu.Lock()
	clients := make([]net.Conn, 0, len(h.Clients))
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
func (h *Host) handle(c net.Conn) {
	defer c.Close()
	dec := json.NewDecoder(bufio.NewReader(c))

	var challenge auth.Challenge
	if err := dec.Decode(&challenge); err != nil || challenge.Type != "auth_challenge" {
		return
	}
	hostResponse, err := auth.RespondAs(h.Identity, &challenge, h.Name)
	if err != nil {
		return
	}
	if err = h.writeJSON(c, hostResponse); err != nil {
		return
	}

	ownChallenge, err := auth.NewChallenge()
	if err != nil {
		return
	}
	if err = h.writeJSON(c, ownChallenge); err != nil {
		return
	}

	var clientResponse auth.Response
	if err = dec.Decode(&clientResponse); err != nil {
		return
	}
	if err = auth.Verify(ownChallenge, &clientResponse); err != nil {
		_ = h.writePacket(c, Packet{Type: "error", Text: "authentication failed"})
		return
	}
	store := auth.Load()
	if err = store.Trust(clientResponse.ID, clientResponse.PublicKey); err != nil {
		_ = h.writePacket(c, Packet{Type: "error", Text: "peer identity key changed; refusing connection"})
		return
	}

	// The nickname is whatever the peer chose to call itself. It is cleaned
	// before it is stored, because from here on it gets printed on other
	// people's terminals.
	member := Member{ID: clientResponse.ID, Name: profile.CleanNickname(clientResponse.Name)}

	// Admission. With group chat off, the room holds one guest and the second
	// is told why rather than being dropped without explanation.
	h.Mu.Lock()
	if !h.group && len(h.members) > 0 {
		h.Mu.Unlock()
		_ = h.writePacket(c, Packet{Type: "error", Text: "this host is already in a chat and has group chat turned off"})
		return
	}
	h.Clients[c] = struct{}{}
	h.members[c] = member
	h.Mu.Unlock()

	peer := Peer{ID: member.ID, Name: member.Name}
	defer func() {
		h.Mu.Lock()
		delete(h.Clients, c)
		delete(h.members, c)
		h.Mu.Unlock()
		h.announce(peer, true)
		if h.Group() {
			h.systemf("%s left", displayOf(member))
			h.sendRoster()
		}
	}()

	if err = h.writePacket(c, Packet{Type: "hello", From: h.ID, Name: h.Name, Group: h.Group()}); err != nil {
		return
	}
	h.announce(peer, false)
	if h.Group() {
		h.broadcastExcept(Packet{Type: "system", Text: fmt.Sprintf("%s joined", displayOf(member))}, c)
		h.sendRoster()
	}

	for {
		var p Packet
		if err := dec.Decode(&p); err != nil {
			return
		}

		// A peer may rename itself mid-session; everything else it says about
		// who it is, is ignored.
		if p.Type == "nick" {
			renamed := Member{ID: member.ID, Name: profile.CleanNickname(p.Name)}
			h.Mu.Lock()
			h.members[c] = renamed
			h.Mu.Unlock()
			if h.Group() && displayOf(renamed) != displayOf(member) {
				h.systemf("%s is now %s", displayOf(member), displayOf(renamed))
				h.sendRoster()
			}
			member = renamed
			continue
		}

		if p.Type != "msg" {
			continue
		}
		if len([]byte(p.Text)) > MaxMessageBytes {
			_ = h.writePacket(c, Packet{Type: "error", Text: "message exceeds 4096 bytes"})
			continue
		}

		// Relay under the identity this connection actually authenticated as,
		// never under the one the packet claims. Without this, any guest could
		// put words in another guest's mouth simply by setting From and Name.
		fmt.Printf("\r[%s] %s\n> ", displayOf(member), p.Text)
		if h.Group() {
			h.broadcastExcept(Packet{Type: "msg", From: member.ID, Name: member.Name, Text: p.Text}, c)
		}
	}
}

// displayOf is the label shown for a member.
func displayOf(m Member) string { return m.Display() }
func (h *Host) writeJSON(c net.Conn, v any) error {
	h.WriteMu.Lock()
	defer h.WriteMu.Unlock()
	// A deadline here is what stops one unresponsive participant holding up
	// every other person in the room; see WriteTimeout.
	_ = c.SetWriteDeadline(time.Now().Add(WriteTimeout))
	defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	return json.NewEncoder(c).Encode(v)
}
func (h *Host) writePacket(c net.Conn, p Packet) error { return h.writeJSON(c, p) }
func (h *Host) broadcast(p Packet, except net.Conn) {
	h.Mu.Lock()
	clients := make([]net.Conn, 0, len(h.Clients))
	for c := range h.Clients {
		if c != except {
			clients = append(clients, c)
		}
	}
	h.Mu.Unlock()
	for _, c := range clients {
		if err := h.writePacket(c, p); err != nil {
			_ = c.Close()
		}
	}
}

// WriteTimeout bounds a single write to one participant.
//
// In a two-person chat a wedged peer only hurt itself. In a room, broadcast
// writes to everyone in turn, so one peer that has stopped reading — suspended
// laptop, dead Wi-Fi, a debugger — would stall the write and freeze the
// conversation for everybody else. A peer that cannot accept a message within
// this window is dropped instead.
const WriteTimeout = 10 * time.Second

// broadcastExcept sends to everyone but one connection, usually the sender.
func (h *Host) broadcastExcept(p Packet, except net.Conn) { h.broadcast(p, except) }
func (h *Host) Broadcast(p Packet) {
	if p.Type == "msg" && len([]byte(p.Text)) > MaxMessageBytes {
		return
	}
	h.broadcast(p, nil)
}

// DialTimeout bounds a direct TCP connection attempt so a black-holed candidate
// cannot stall the connection strategy.
const DialTimeout = 8 * time.Second

// HandleConn serves one already-established transport as the host side.
//
// The transport may be a plain TCP connection or a relayed byte pipe; the TLS
// session and the CMD-Chat handshake are identical either way, which is what
// keeps the relay out of the trust model.
func (h *Host) HandleConn(raw net.Conn) { h.handle(tls.Server(raw, h.TLSConfig)) }

func Client(address, expectedFingerprint, expectedHostID, id, name string, ident *identity.Identity) (net.Conn, *json.Decoder, error) {
	raw, err := net.DialTimeout("tcp", address, DialTimeout)
	if err != nil {
		return nil, nil, err
	}
	return ClientConn(raw, expectedFingerprint, expectedHostID, id, name, ident)
}

// ClientConn runs the client handshake over an already-established transport.
//
// Certificate pinning and the mutual Ed25519 challenge happen here, end to end,
// so a relayed connection is authenticated exactly as strictly as a direct one:
// a relay that tampered with the stream would fail the fingerprint check.
func ClientConn(raw net.Conn, expectedFingerprint, expectedHostID, id, name string, ident *identity.Identity) (net.Conn, *json.Decoder, error) {
	c := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = c.Close()
		return nil, nil, errors.New("host sent no certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	actual := hex.EncodeToString(sum[:])
	expected := strings.TrimSpace(expectedFingerprint)
	if expected != "" && !strings.EqualFold(actual, expected) {
		_ = c.Close()
		return nil, nil, fmt.Errorf("host fingerprint mismatch")
	}
	if expected == "" {
		fmt.Println("Warning: host certificate is not pinned; identity authentication is still required.")
	}
	reader := bufio.NewReader(c)
	dec := json.NewDecoder(reader)
	challenge, err := auth.NewChallenge()
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	if err = json.NewEncoder(c).Encode(challenge); err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	var hostResponse auth.Response
	if err = dec.Decode(&hostResponse); err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	if err = auth.Verify(challenge, &hostResponse); err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("host identity authentication failed: %w", err)
	}
	if expectedHostID != "" && hostResponse.ID != expectedHostID {
		_ = c.Close()
		return nil, nil, fmt.Errorf("host identity mismatch: expected %s, got %s", expectedHostID, hostResponse.ID)
	}
	store := auth.Load()
	if err = store.Trust(hostResponse.ID, hostResponse.PublicKey); err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("trusted host key changed: %w", err)
	}
	var hostChallenge auth.Challenge
	if err = dec.Decode(&hostChallenge); err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	response, err := auth.RespondAs(ident, &hostChallenge, profile.CleanNickname(name))
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	if err = json.NewEncoder(c).Encode(response); err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	return c, dec, nil
}

// Rename tells the host this guest is now called something else, so the roster
// and the labels on its messages follow without reconnecting.
func Rename(c net.Conn, name string) error {
	return json.NewEncoder(c).Encode(Packet{Type: "nick", Name: profile.CleanNickname(name)})
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

func Send(c net.Conn, p Packet) error {
	if p.Type == "msg" && len([]byte(p.Text)) > MaxMessageBytes {
		return fmt.Errorf("message exceeds %d bytes", MaxMessageBytes)
	}
	return json.NewEncoder(c).Encode(p)
}

// ReadLoop delivers packets until the connection ends.
//
// It prints nothing. The caller already announces that the chat closed, and
// when the caller is the one who closed it — /quit — the socket error is an
// implementation detail the user should never have seen. It used to print
// "Connection closed: use of closed network connection" after every /quit.
func ReadLoop(dec *json.Decoder, onMessage func(Packet)) {
	for {
		var p Packet
		if err := dec.Decode(&p); err != nil {
			if err != io.EOF {
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

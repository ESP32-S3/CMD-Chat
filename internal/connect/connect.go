// Package connect chooses how two CMD-Chat peers reach each other.
//
// The order is fixed and always tried in full before falling back:
//
//  1. LAN discovery      - UDP broadcast, same network only
//  2. direct TCP         - candidates from the phonebook, IPv6 and IPv4 raced
//     in parallel so one black-holed address cannot stall
//     the others
//  3. relay              - authenticated byte pipe, used only when every direct
//     path has failed
//
// Direct connections are preferred at every step; the relay exists so that two
// ordinary users behind NAT can still talk, not to replace peer-to-peer. The
// transport chosen here carries the same TLS session and the same mutual
// Ed25519 handshake in all three cases, so the security properties do not
// depend on which path won.
package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/chat"
	"github.com/ESP32-S3/CMD-Chat/internal/discovery"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/phonebook"
	"github.com/ESP32-S3/CMD-Chat/internal/relay"
)

// RelayProtocolVersion is the phonebook protocol_version a host publishes to
// advertise that it is also waiting on the relay. Using the existing version
// field avoids a schema change: hosts publishing 1 simply have no relay.
const RelayProtocolVersion = 2

// Default time budgets. Every stage is bounded so a failed path degrades to the
// next one quickly instead of hanging the application.
const (
	DefaultLANTimeout    = 3 * time.Second
	DefaultDirectTimeout = 8 * time.Second
	DefaultRelayTimeout  = 25 * time.Second
)

// Logf receives short, user-facing progress lines. Addresses are deliberately
// summarised rather than printed in full; verbose detail belongs in debug logs.
type Logf func(format string, args ...any)

// Path names the transport that won.
type Path string

const (
	PathLAN    Path = "lan"
	PathDirect Path = "direct"
	PathRelay  Path = "relay"
)

// Result is an established transport, before any TLS handshake.
type Result struct {
	Conn   net.Conn
	Path   Path
	Detail string

	// HostID is the identity the caller must require the peer to prove.
	//
	// It is ALWAYS the ID the user typed, never one that came back from the
	// phonebook, from a LAN broadcast, or from the relay. Those are all
	// attacker-influenced channels, and on first contact the trust store has
	// nothing to catch a substitution with. Pinning the user's own input is what
	// makes the first exchange safe: the ID is a hash of the peer's public key,
	// so typing it already commits to that exact key.
	HostID string

	// Fingerprint is the TLS certificate fingerprint the directory published, or
	// empty. It is defence in depth only — it arrives over the same channel as
	// everything else here, so it is never the thing being trusted.
	Fingerprint string
}

// Options configures a join attempt.
type Options struct {
	Identity      *identity.Identity
	PhonebookURL  string
	RelayURL      string
	Log           Logf
	Debug         Logf
	LANTimeout    time.Duration
	DirectTimeout time.Duration
	RelayTimeout  time.Duration

	// Force pins the strategy to a single transport instead of falling back
	// through all of them. Empty means the normal automatic behaviour; the
	// other values exist for diagnosing which paths actually work on a given
	// network, and for exercising the relay when a direct path would win.
	Force Path
}

func (o *Options) applyDefaults() {
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Debug == nil {
		o.Debug = func(string, ...any) {}
	}
	if o.LANTimeout == 0 {
		o.LANTimeout = DefaultLANTimeout
	}
	if o.DirectTimeout == 0 {
		o.DirectTimeout = DefaultDirectTimeout
	}
	if o.RelayTimeout == 0 {
		o.RelayTimeout = DefaultRelayTimeout
	}
}

// ErrUnreachable is returned when every path in the strategy has been tried.
var ErrUnreachable = errors.New("connect: peer could not be reached by any available path")

// Join runs the full connection strategy for a target CMD-Chat ID.
//
// The returned Result holds a live transport; the caller performs the TLS and
// identity handshake on it via chat.ClientConn.
func Join(target string, opts Options) (*Result, error) {
	opts.applyDefaults()

	if opts.Force != "" {
		opts.Log("[network] transport pinned to %q by configuration", opts.Force)
	}

	if opts.Force == "" || opts.Force == PathLAN {
		if result := tryLAN(target, &opts); result != nil {
			return result, nil
		}
		if opts.Force == PathLAN {
			return nil, fmt.Errorf("%w: not reachable on the local network", ErrUnreachable)
		}
	}

	peer, err := lookup(target, &opts)
	if err != nil {
		return nil, err
	}

	if opts.Force == "" || opts.Force == PathDirect {
		if result := tryDirect(target, peer, &opts); result != nil {
			return result, nil
		}
		if opts.Force == PathDirect {
			return nil, fmt.Errorf("%w: no direct path to the peer", ErrUnreachable)
		}
	}

	return tryRelay(target, peer, &opts)
}

// ForceFromEnv reads the CMD_CHAT_TRANSPORT diagnostic override. Unrecognised
// values are ignored so a typo degrades to normal behaviour rather than
// breaking connectivity.
func ForceFromEnv() Path {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CMD_CHAT_TRANSPORT"))) {
	case "lan":
		return PathLAN
	case "direct":
		return PathDirect
	case "relay":
		return PathRelay
	default:
		return ""
	}
}

func tryLAN(target string, opts *Options) *Result {
	opts.Log("[network] searching the local network")
	found, err := discovery.Find(target, opts.LANTimeout)
	if err != nil {
		opts.Debug("LAN discovery failed: %v", err)
		return nil
	}
	if len(found) == 0 {
		opts.Log("[network] not found on the local network")
		return nil
	}

	a := found[0]
	opts.Debug("LAN candidate id=%q endpoint=%q", a.ID, a.Endpoint)
	conn, err := net.DialTimeout("tcp", a.Endpoint, chat.DialTimeout)
	if err != nil {
		opts.Debug("LAN dial failed: %v", err)
		opts.Log("[network] local network host did not answer")
		return nil
	}

	opts.Log("[network] connected over the local network")
	// HostID is the caller's target, not a.ID: an announcement is unauthenticated.
	return &Result{Conn: conn, Path: PathLAN, Detail: "LAN", HostID: target, Fingerprint: a.Fingerprint}
}

func lookup(target string, opts *Options) (*phonebook.Peer, error) {
	opts.Log("[network] looking up the peer in the phonebook")
	client := phonebook.New(opts.Identity, opts.PhonebookURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	peer, err := client.Lookup(ctx, target)
	if err != nil {
		switch {
		case errors.Is(err, phonebook.ErrNotFound):
			opts.Log("[network] that ID has never been listed in the phonebook")
		case errors.Is(err, phonebook.ErrOffline):
			opts.Log("[network] peer is listed but not currently online")
		default:
			opts.Log("[network] phonebook lookup failed")
		}
		opts.Debug("phonebook lookup for %q failed: %v", target, err)
		return nil, err
	}

	opts.Log("[network] peer found (%d address candidate(s))", len(peer.Candidates))
	opts.Debug("phonebook resolved %s: version=%d candidates=%d", peer.ID, peer.Version, len(peer.Candidates))
	return peer, nil
}

func tryDirect(target string, peer *phonebook.Peer, opts *Options) *Result {
	endpoints := peer.TCPEndpoints()
	if len(endpoints) == 0 {
		opts.Log("[network] no direct address available for this peer")
		return nil
	}

	opts.Log("[network] attempting direct connection")
	conn, endpoint, err := dialFastest(endpoints, opts.DirectTimeout, opts.Debug)
	if err != nil {
		opts.Log("[network] direct connection failed")
		opts.Debug("all %d direct candidate(s) failed: %v", len(endpoints), err)
		return nil
	}

	family := addressFamily(endpoint)
	opts.Log("[network] direct connection succeeded (%s)", family)
	opts.Debug("direct connection established to %s", endpoint)
	return &Result{Conn: conn, Path: PathDirect, Detail: family, HostID: target, Fingerprint: peer.Fingerprint}
}

// dialFastest races every candidate at once and keeps the first that answers.
//
// Racing matters: a peer typically publishes a mix of LAN, IPv6 and IPv4
// addresses, and the unreachable ones usually fail by timing out rather than
// refusing. Trying them one at a time would multiply the worst case by the
// number of candidates.
func dialFastest(endpoints []string, budget time.Duration, debug Logf) (net.Conn, string, error) {
	type outcome struct {
		conn     net.Conn
		endpoint string
		err      error
	}

	results := make(chan outcome, len(endpoints))
	var wg sync.WaitGroup

	perDial := budget
	if perDial > chat.DialTimeout {
		perDial = chat.DialTimeout
	}

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", endpoint, perDial)
			results <- outcome{conn: conn, endpoint: endpoint, err: err}
		}(endpoint)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	deadline := time.After(budget)
	var winner net.Conn
	var winnerEndpoint string
	var lastErr error
	remaining := len(endpoints)

	for remaining > 0 {
		select {
		case out, ok := <-results:
			if !ok {
				remaining = 0
				continue
			}
			remaining--
			if out.err != nil {
				debug("candidate %s failed: %v", out.endpoint, out.err)
				lastErr = out.err
				continue
			}
			if winner == nil {
				winner = out.conn
				winnerEndpoint = out.endpoint
				continue
			}
			// A slower candidate also connected; keep the first.
			out.conn.Close()
		case <-deadline:
			remaining = 0
		}
		if winner != nil {
			break
		}
	}

	// Drain the stragglers in the background so nothing is leaked.
	go func() {
		for out := range results {
			if out.conn != nil && out.conn != winner {
				out.conn.Close()
			}
		}
	}()

	if winner == nil {
		if lastErr == nil {
			lastErr = errors.New("no candidate answered in time")
		}
		return nil, "", lastErr
	}
	return winner, winnerEndpoint, nil
}

func tryRelay(target string, peer *phonebook.Peer, opts *Options) (*Result, error) {
	if peer.Version < RelayProtocolVersion {
		opts.Log("[network] peer's client does not support the relay")
		return nil, fmt.Errorf("%w: no direct path and the peer predates relay support", ErrUnreachable)
	}

	opts.Log("[network] attempting relay")
	session, err := relay.Dial(opts.RelayURL, peer.ID, opts.Identity)
	if err != nil {
		switch {
		case errors.Is(err, relay.ErrNoHost):
			opts.Log("[network] peer is not waiting on the relay")
		case errors.Is(err, relay.ErrSessionBusy):
			opts.Log("[network] peer is already in another chat")
		default:
			opts.Log("[network] relay connection failed")
		}
		opts.Debug("relay dial failed: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}

	opts.Log("[network] relay connection established")
	opts.Debug("relay paired with %s", session.PeerID)
	// session.PeerID is the relay's word for who it paired us with, and is used
	// for logging only. The identity that must be PROVEN is still the target.
	return &Result{Conn: session.Conn, Path: PathRelay, Detail: "relay", HostID: target, Fingerprint: peer.Fingerprint}, nil
}

// addressFamily summarises an endpoint for logging without printing the address.
func addressFamily(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "direct"
	}
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return "direct"
	case ip.To4() != nil && ip.IsPrivate():
		return "IPv4, private"
	case ip.To4() != nil:
		return "IPv4"
	default:
		return "IPv6"
	}
}

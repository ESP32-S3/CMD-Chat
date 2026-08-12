// Package relay is the client for the CMD-Chat relay: a fallback byte pipe for
// peers that cannot reach each other directly.
//
// The relay is the LAST resort. Callers try LAN discovery, then direct IPv6 and
// IPv4 candidates from the phonebook, and only come here when every direct path
// has failed.
//
// What crosses the relay is the peers' existing TLS 1.3 session, unchanged. The
// relay moves opaque binary frames and holds none of the keys, so it cannot read
// or forge a message, and the guest still pins the host's certificate
// fingerprint exactly as it does on a LAN. A hostile relay can drop or delay
// traffic — it cannot become a man in the middle.
//
// Authentication reuses the Ed25519 identity CMD-Chat already has. A session is
// named after its host's CMD-Chat ID, and because an ID is a hash of its public
// key, only the host's key can claim the host slot.
package relay

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// DefaultBaseURL is the deployed relay. Override with CMD_CHAT_RELAY_URL.
const DefaultBaseURL = "https://cmd-chat-relay.cmd-chat.workers.dev"

// BaseURLEnv names the environment variable that overrides DefaultBaseURL.
const BaseURLEnv = "CMD_CHAT_RELAY_URL"

const signingPrefix = "cmd-chat-relay/v1"

// Timeouts. Direct connection attempts must fail fast, so the relay is reached
// quickly; once relayed, a host may wait a long time for a guest.
const (
	handshakeTimeout = 15 * time.Second
	pairTimeout      = 20 * time.Second
)

// Errors callers branch on.
var (
	// ErrNoHost means the peer is not waiting on the relay.
	ErrNoHost = errors.New("relay: peer is not reachable through the relay")
	// ErrSessionBusy means the host is already in a relayed chat.
	ErrSessionBusy = errors.New("relay: peer is already in a relayed chat")
	// ErrWaitTimeout means no peer joined within the wait window. For a host
	// this is the ordinary idle case, not a failure.
	ErrWaitTimeout = errors.New("relay: timed out waiting for the peer")
)

// BaseURL reports the relay to use, honouring CMD_CHAT_RELAY_URL.
func BaseURL() string {
	if v := strings.TrimSpace(os.Getenv(BaseURLEnv)); v != "" {
		return v
	}
	return DefaultBaseURL
}

// Session is a paired relay connection ready to carry a TLS session.
type Session struct {
	// Conn carries opaque bytes to the peer. Wrap it in tls.Client or
	// tls.Server; never write plaintext to it.
	Conn net.Conn

	// PeerID is the CMD-Chat ID the relay authenticated on the other side.
	// It is a hint for logging only: the authoritative identity check is the
	// end-to-end handshake in internal/auth, which the relay cannot influence.
	PeerID string

	closeOnce sync.Once
}

// Close tears down the relayed connection.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.Conn.Close() })
	return err
}

func websocketURL(baseURL, session string) string {
	trimmed := strings.TrimRight(baseURL, "/")
	switch {
	case strings.HasPrefix(trimmed, "https://"):
		trimmed = "wss://" + trimmed[len("https://"):]
	case strings.HasPrefix(trimmed, "http://"):
		trimmed = "ws://" + trimmed[len("http://"):]
	}
	return trimmed + "/relay/" + session
}

// authHeaders proves possession of the identity's private key for this exact
// role and session. Binding both means a captured signature cannot be replayed
// to join a different session or to claim the host slot.
func authHeaders(ident *identity.Identity, role, session string) http.Header {
	issuedAt := time.Now().UnixMilli()
	message := strings.Join([]string{signingPrefix, role, session, ident.ID, strconv.FormatInt(issuedAt, 10)}, "\n")

	h := http.Header{}
	h.Set("X-CmdChat-Role", role)
	h.Set("X-CmdChat-Id", ident.ID)
	h.Set("X-CmdChat-PublicKey", base64.StdEncoding.EncodeToString(ident.PublicKey))
	h.Set("X-CmdChat-IssuedAt", strconv.FormatInt(issuedAt, 10))
	h.Set("X-CmdChat-Signature", base64.StdEncoding.EncodeToString(ident.Sign([]byte(message))))
	return h
}

// control is a relay control message. These travel as text frames and are never
// mixed into the relayed byte stream.
type control struct {
	Type    string `json:"type"`
	Peer    string `json:"peer"`
	Code    string `json:"error"`
	Message string `json:"message"`
}

func decodeControl(raw []byte, out *control) error { return json.Unmarshal(raw, out) }

func translateDialError(err error) error {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		switch {
		case strings.Contains(httpErr.Body, `"no_host"`):
			return ErrNoHost
		case strings.Contains(httpErr.Body, `"session_busy"`):
			return ErrSessionBusy
		}
	}
	return err
}

// Listen connects to the relay as the host of its own session and waits for a
// guest. It returns once a peer has been paired.
//
// The session name is the host's own ID, so no coordination is needed: a guest
// that knows the host's CMD-Chat ID already knows where to look.
func Listen(baseURL string, ident *identity.Identity, wait time.Duration) (*Session, error) {
	conn, err := dialWebSocket(websocketURL(baseURL, ident.ID), authHeaders(ident, "host", ident.ID), handshakeTimeout)
	if err != nil {
		return nil, translateDialError(err)
	}

	peer, err := awaitPeer(conn, wait)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Session{Conn: conn, PeerID: peer}, nil
}

// Dial joins the relay session belonging to host, as a guest.
//
// It returns ErrNoHost when the host is not currently waiting on the relay,
// which the caller should treat as "peer offline" rather than as a relay fault.
func Dial(baseURL, host string, ident *identity.Identity) (*Session, error) {
	conn, err := dialWebSocket(websocketURL(baseURL, host), authHeaders(ident, "guest", host), handshakeTimeout)
	if err != nil {
		return nil, translateDialError(err)
	}

	peer, err := awaitPeer(conn, pairTimeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Session{Conn: conn, PeerID: peer}, nil
}

// awaitPeer blocks until the relay reports both sides present.
func awaitPeer(conn *wsConn, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", ErrWaitTimeout
		}

		raw, err := conn.nextControl(remaining)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return "", ErrWaitTimeout
			}
			return "", err
		}

		var msg control
		if err := decodeControl(raw, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "paired":
			return msg.Peer, nil
		case "waiting":
			continue
		case "peer_left":
			continue
		case "error":
			return "", fmt.Errorf("relay: %s (%s)", msg.Message, msg.Code)
		}
	}
}

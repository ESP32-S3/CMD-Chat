// Package phonebook is the client for the CMD-Chat rendezvous directory.
//
// It is the wide-area counterpart to internal/discovery: where discovery finds
// a host by UDP broadcast on the same LAN, phonebook finds one anywhere by
// asking a Cloudflare Worker backed by a D1 table.
//
// The directory is used for DISCOVERY ONLY. It never carries chat traffic and
// never sees a private key: it stores an ID, a public key, the session TLS
// fingerprint, and a short-lived list of connection candidates. Once a peer has
// been resolved the two clients talk directly, exactly as they do on a LAN.
//
// Resolving a peer does not guarantee reaching it. See network.Order(): the
// phonebook covers the NATTraversal stage of that sequence, and NAT traversal
// can still fail on restrictive networks.
package phonebook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// DefaultBaseURL is the deployed phonebook Worker. Override it with the
// CMD_CHAT_PHONEBOOK_URL environment variable, or by setting Client.BaseURL;
// the URL is not repeated anywhere else in the codebase.
const DefaultBaseURL = "https://cmd-chat-phonebook.cmd-chat.workers.dev"

// BaseURLEnv names the environment variable that overrides DefaultBaseURL.
const BaseURLEnv = "CMD_CHAT_PHONEBOOK_URL"

// BaseURL reports the directory to use: the CMD_CHAT_PHONEBOOK_URL environment
// variable when set, otherwise DefaultBaseURL. Callers should use this rather
// than referring to DefaultBaseURL directly, so the URL stays configurable from
// exactly one place.
func BaseURL() string {
	if v := strings.TrimSpace(os.Getenv(BaseURLEnv)); v != "" {
		return v
	}
	return DefaultBaseURL
}

// signingPrefix domain-separates phonebook signatures from the CMD-CHAT/1
// handshake signatures in internal/auth, so neither can be replayed as the other.
const signingPrefix = "cmd-chat-phonebook/v1"

const (
	signatureHeader = "X-CmdChat-Signature"
	maxResponseSize = 64 << 10
	defaultTimeout  = 10 * time.Second
)

// Candidate kinds understood by the directory.
const (
	KindHost            = "host"
	KindServerReflexive = "server_reflexive"
	// KindServerReflexiveHTTP is added by the Worker itself: the public IP it
	// saw. It carries no port, because the source port of an HTTPS request is
	// not the port a hole-punching socket will use.
	KindServerReflexiveHTTP = "server_reflexive_http"
)

// Errors callers are expected to branch on.
var (
	// ErrNotFound means the ID has never registered.
	ErrNotFound = errors.New("phonebook: no such CMD-Chat ID")
	// ErrOffline means the ID is known but its registration is stale or revoked.
	ErrOffline = errors.New("phonebook: peer is offline")
	// ErrNotRegistered is returned by Heartbeat when the registration has lapsed.
	ErrNotRegistered = errors.New("phonebook: no active registration")
)

// APIError is a structured failure reported by the Worker.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("phonebook: %s (%s, HTTP %d)", e.Message, e.Code, e.Status)
}

// Candidate is one address a peer might be reachable on.
type Candidate struct {
	Kind      string `json:"kind"`
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Port      *int   `json:"port"`
	Priority  int    `json:"priority"`
}

// Announcement is what a host publishes about itself.
type Announcement struct {
	// Fingerprint is the host's TLS certificate fingerprint for this session,
	// as produced by chat.NewHost. Joiners pin it, so publishing it here is
	// what makes a phonebook-resolved connection as safe as a LAN one.
	Fingerprint string
	Candidates  []Candidate
}

// Peer is a resolved directory entry.
type Peer struct {
	ID          string      `json:"id"`
	Online      bool        `json:"online"`
	PublicKey   string      `json:"public_key"`
	Fingerprint string      `json:"session_fingerprint"`
	Version     int         `json:"protocol_version"`
	LastSeen    int64       `json:"last_seen"`
	ExpiresAt   int64       `json:"expires_at"`
	Candidates  []Candidate `json:"candidates"`
}

// Registration is the outcome of a successful Register or Heartbeat.
type Registration struct {
	ID                string `json:"id"`
	ExpiresAt         int64  `json:"expires_at"`
	TTL               int    `json:"ttl"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
	ObservedIP        string `json:"observed_ip"`
}

// HeartbeatInterval reports how often the host should call Heartbeat.
func (r Registration) HeartbeatIntervalDuration() time.Duration {
	if r.HeartbeatInterval <= 0 {
		return 60 * time.Second
	}
	return time.Duration(r.HeartbeatInterval) * time.Second
}

// Client talks to the phonebook on behalf of one identity.
type Client struct {
	BaseURL       string
	HTTP          *http.Client
	Identity      *identity.Identity
	ClientVersion string

	mu           sync.Mutex
	lastIssuedAt int64
}

// New builds a Client for the given identity using the configured base URL.
func New(id *identity.Identity, baseURL string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL:       strings.TrimRight(baseURL, "/"),
		HTTP:          &http.Client{Timeout: defaultTimeout},
		Identity:      id,
		ClientVersion: "0.1.0",
	}
}

// nextIssuedAt returns a strictly increasing millisecond timestamp.
//
// The directory rejects any request whose issued_at is not newer than the last
// one it accepted for this ID; that is what makes captured requests unreplayable.
// Two calls inside the same millisecond must therefore not collide.
func (c *Client) nextIssuedAt() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UnixMilli()
	if now <= c.lastIssuedAt {
		now = c.lastIssuedAt + 1
	}
	c.lastIssuedAt = now
	return now
}

// sign produces the Ed25519 signature the Worker verifies. Only the signature
// and the public key travel; the private key never leaves this process.
func (c *Client) sign(method, path string, issuedAt int64, body []byte) string {
	sum := sha256.Sum256(body)
	message := strings.Join([]string{
		signingPrefix,
		strings.ToUpper(method),
		path,
		strconv.FormatInt(issuedAt, 10),
		hex.EncodeToString(sum[:]),
	}, "\n")
	return base64.StdEncoding.EncodeToString(c.Identity.Sign([]byte(message)))
}

func (c *Client) publicKey() string {
	return base64.StdEncoding.EncodeToString(c.Identity.PublicKey)
}

type apiEnvelope struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// do sends a request, signing it when a body is supplied, and returns the raw
// JSON payload for the caller to decode.
func (c *Client) do(ctx context.Context, method, path string, payload map[string]any) ([]byte, error) {
	var body []byte
	if payload != nil {
		payload["id"] = c.Identity.ID
		payload["public_key"] = c.publicKey()
		payload["issued_at"] = c.nextIssuedAt()
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = encoded
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		issuedAt, _ := payload["issued_at"].(int64)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(signatureHeader, c.sign(method, path, issuedAt, body))
	}

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("phonebook: %s %s: %w", method, path, err)
	}
	defer res.Body.Close()

	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}

	var envelope apiEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("phonebook: malformed response from %s (HTTP %d)", path, res.StatusCode)
	}
	if !envelope.OK {
		switch envelope.Error {
		case "not_found":
			return data, ErrNotFound
		case "offline":
			return data, ErrOffline
		case "not_registered":
			return data, ErrNotRegistered
		}
		return data, &APIError{Status: res.StatusCode, Code: envelope.Error, Message: envelope.Message}
	}
	return data, nil
}

// Register publishes this identity's connection candidates, replacing any
// previous entry for the same ID. Call it when hosting starts.
func (c *Client) Register(ctx context.Context, a Announcement) (*Registration, error) {
	if len(a.Candidates) == 0 {
		return nil, errors.New("phonebook: refusing to register with no connection candidates")
	}
	payload := map[string]any{
		"protocol_version": 1,
		"client_version":   c.ClientVersion,
		"candidates":       a.Candidates,
	}
	if a.Fingerprint != "" {
		payload["session_fingerprint"] = strings.ToLower(a.Fingerprint)
	}

	data, err := c.do(ctx, http.MethodPost, "/register", payload)
	if err != nil {
		return nil, err
	}
	var out Registration
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat extends the registration TTL. It cannot change identity or
// candidates; use Register for that.
func (c *Client) Heartbeat(ctx context.Context) (*Registration, error) {
	data, err := c.do(ctx, http.MethodPost, "/heartbeat", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out Registration
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unregister revokes this identity's entry and destroys its stored addresses.
func (c *Client) Unregister(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodDelete, "/register/"+c.Identity.ID, map[string]any{})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// Lookup resolves another CMD-Chat ID. It returns ErrOffline when the peer is
// known but stale, which callers should treat as "not reachable right now"
// rather than as a hard failure.
func (c *Client) Lookup(ctx context.Context, id string) (*Peer, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("phonebook: %q is not a valid CMD-Chat ID", id)
	}
	data, err := c.do(ctx, http.MethodGet, "/lookup/"+id, nil)
	if err != nil {
		return nil, err
	}
	var peer Peer
	if err := json.Unmarshal(data, &peer); err != nil {
		return nil, err
	}
	return &peer, nil
}

// KeepAlive heartbeats until ctx is cancelled. It is intended to run in a
// goroutine for as long as the host is serving. Transient failures are reported
// to onError (if set) but do not stop the loop; a lapsed registration is
// re-established by calling renew.
func (c *Client) KeepAlive(ctx context.Context, every time.Duration, renew func(context.Context) error, onError func(error)) {
	if every <= 0 {
		every = 60 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, err := c.Heartbeat(ctx)
			if errors.Is(err, ErrNotRegistered) && renew != nil {
				err = renew(ctx)
			}
			if err != nil && onError != nil && ctx.Err() == nil {
				onError(err)
			}
		}
	}
}

// ValidID reports whether id has the shape produced by identity.LoadOrCreate:
// "cc-" followed by 16 RFC 4648 base32 characters.
func ValidID(id string) bool {
	if len(id) != 19 || !strings.HasPrefix(id, "cc-") {
		return false
	}
	for _, r := range id[3:] {
		if !(r >= 'A' && r <= 'Z') && !(r >= '2' && r <= '7') {
			return false
		}
	}
	return true
}

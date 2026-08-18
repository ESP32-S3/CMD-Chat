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
	"crypto/ed25519"
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

// signingPrefix domain-separates phonebook signatures from every other
// signature in CMD-Chat, so none can be replayed as another.
//
// The v2 prefix goes with the v2 endpoints and the derived write key. A v1
// signature can never be accepted as a v2 one, or the reverse.
const signingPrefix = "cmd-chat-phonebook/v2"

const (
	signatureHeader = "X-CmdChat-Signature"
	maxResponseSize = 64 << 10
	defaultTimeout  = 10 * time.Second
)

// Candidate kinds understood by the directory.
const (
	KindHost            = "host"
	KindServerReflexive = "server_reflexive"
	// KindServerReflexiveHTTP was the public IP the Worker itself observed and
	// stored.
	//
	// Nothing produces it any more. It was the single most direct
	// identity-to-location record in the directory — written for every peer that
	// registered, including ones that published no addresses at all — and it was
	// never read back, because only 'host' candidates are ever dialled. The
	// Worker now reports the observed address to the caller and stores nothing.
	//
	// The constant remains so a v1 entry from an older client still parses.
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
	// ErrHandleClaimed means another write key already owns this directory
	// handle. See the trade documented in handle.go: it means somebody who knows
	// this ID published under it first. It blocks wide-area discovery; it does
	// not let them read or impersonate anything.
	ErrHandleClaimed = errors.New("phonebook: this directory handle is already claimed by another key")
	// ErrDirectoryOutdated means the directory Worker does not implement the
	// blinded v2 endpoints yet.
	ErrDirectoryOutdated = errors.New("phonebook: the directory has not been updated to the blinded protocol")
	// ErrDirectoryMismatch means the directory answered a lookup with an entry
	// that is not the one that was asked for. It is treated as a hostile
	// directory, not as a transient fault, and the caller must not connect.
	ErrDirectoryMismatch = errors.New("phonebook: the directory answered with the wrong peer")
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

	// ProtocolVersion advertises what this host supports. Version 2 means the
	// host is also waiting on the relay, so a peer with no direct path can
	// still reach it. Zero defaults to 1. Reusing this existing field is why
	// relay support needed no phonebook schema change.
	ProtocolVersion int
}

// Peer is a resolved directory entry, after the sealed record has been opened.
//
// There is no PublicKey field any more, and there is deliberately nowhere to put
// one. The directory no longer carries a peer's identity key, because it no
// longer knows which identity an entry belongs to — and nothing needed it: the
// ID is a hash of the key, and the CMDC2 handshake proves the key end to end.
type Peer struct {
	ID          string
	Online      bool
	Fingerprint string
	Version     int
	LastSeen    int64
	ExpiresAt   int64
	Candidates  []Candidate
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
	BaseURL         string
	HTTP            *http.Client
	Identity        *identity.Identity
	derivedWriteKey ed25519.PrivateKey
	ClientVersion   string

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

// sign produces the Ed25519 signature the Worker verifies.
//
// It signs with the DERIVED write key, never the identity key. That is what
// keeps the identity out of the directory: the Worker needs a public key to
// verify against, and this one is unlinkable to who the writer actually is.
func (c *Client) sign(method, path string, issuedAt int64, body []byte) (string, error) {
	writeKey, err := c.writeKey()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	message := strings.Join([]string{
		signingPrefix,
		strings.ToUpper(method),
		path,
		strconv.FormatInt(issuedAt, 10),
		hex.EncodeToString(sum[:]),
	}, "\n")
	return base64.StdEncoding.EncodeToString(ed25519.Sign(writeKey, []byte(message))), nil
}

// writeKey returns the derived directory write key, computing it once.
func (c *Client) writeKey() (ed25519.PrivateKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.derivedWriteKey == nil {
		key, err := WriteKey(c.Identity)
		if err != nil {
			return nil, err
		}
		c.derivedWriteKey = key
	}
	return c.derivedWriteKey, nil
}

// writePublicKey is the base64 write key the Worker binds to this handle.
func (c *Client) writePublicKey() (string, error) {
	key, err := c.writeKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}

// handle is this identity's own blinded directory key.
func (c *Client) handle() (string, error) { return Handle(c.Identity.ID) }

type apiEnvelope struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// do sends a request, signing it when a body is supplied, and returns the raw
// JSON payload for the caller to decode.
func (c *Client) do(ctx context.Context, method, path string, payload map[string]any) ([]byte, error) {
	var body []byte
	var signature string
	if payload != nil {
		// The handle and the derived write key go on the wire. The CMD-Chat ID
		// and the identity public key never do.
		handle, err := c.handle()
		if err != nil {
			return nil, err
		}
		writePub, err := c.writePublicKey()
		if err != nil {
			return nil, err
		}
		issuedAt := c.nextIssuedAt()
		payload["handle"] = handle
		payload["write_key"] = writePub
		payload["issued_at"] = issuedAt

		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = encoded
		if signature, err = c.sign(method, path, issuedAt, body); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(signatureHeader, signature)
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
		case "handle_claimed":
			return data, ErrHandleClaimed
		}
		// A Worker that predates the blinded directory has no v2 routes at all.
		// Say so, rather than reporting it as a mysterious 404.
		if res.StatusCode == http.StatusNotFound && strings.HasPrefix(path, "/v2/") {
			return data, ErrDirectoryOutdated
		}
		return data, &APIError{Status: res.StatusCode, Code: envelope.Error, Message: envelope.Message}
	}
	return data, nil
}

// Register publishes this identity's connection candidates, replacing any
// previous entry.
//
// Everything that could locate the user — every address, and the session
// fingerprint — is sealed before it leaves this process. What the directory
// receives is a blinded handle, an unlinkable write key, and a blob it cannot
// read. See handle.go.
func (c *Client) Register(ctx context.Context, a Announcement) (*Registration, error) {
	if len(a.Candidates) == 0 {
		return nil, errors.New("phonebook: refusing to register with no connection candidates")
	}
	version := a.ProtocolVersion
	if version <= 0 {
		version = 1
	}

	a.ProtocolVersion = version
	_, sealed, err := SealAnnouncement(c.Identity.ID, a, c.ClientVersion)
	if err != nil {
		return nil, err
	}

	data, err := c.do(ctx, http.MethodPost, "/v2/publish", map[string]any{"sealed": sealed})
	if err != nil {
		return nil, err
	}
	var out Registration
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	// The Worker no longer stores the address it observed; it only reports it
	// back so the caller can see its own public IP. Nothing is written down.
	out.ID = c.Identity.ID
	return &out, nil
}

// Heartbeat extends the entry's TTL.
//
// This is the steady-state call, and it is deliberately the cheapest thing the
// directory can do: one row touched, no ciphertext rewritten, nothing re-read.
// Use Register when the sealed contents actually change.
func (c *Client) Heartbeat(ctx context.Context) (*Registration, error) {
	data, err := c.do(ctx, http.MethodPost, "/v2/touch", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out Registration
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	out.ID = c.Identity.ID
	return &out, nil
}

// Unregister revokes this identity's entry and destroys the stored blob.
func (c *Client) Unregister(ctx context.Context) error {
	handle, err := c.handle()
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, "/v2/entry/"+handle, map[string]any{})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// Lookup resolves another CMD-Chat ID.
//
// The ID is never sent. It is blinded to a handle, the sealed entry that comes
// back is opened locally, and an entry that will not open is treated exactly
// like one for the wrong peer: ErrDirectoryMismatch, do not connect. That is
// stronger than the v1 check it replaces — a hostile directory cannot even
// return a well-formed answer for somebody else, because it cannot produce a
// blob that opens under this ID's key.
func (c *Client) Lookup(ctx context.Context, id string) (*Peer, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("phonebook: %q is not a valid CMD-Chat ID", id)
	}
	handle, err := Handle(id)
	if err != nil {
		return nil, err
	}

	data, err := c.do(ctx, http.MethodGet, "/v2/entry/"+handle, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Sealed    string `json:"sealed"`
		Online    bool   `json:"online"`
		LastSeen  int64  `json:"last_seen"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	if !response.Online {
		return nil, ErrOffline
	}

	opened, err := open(id, handle, response.Sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDirectoryMismatch, err)
	}

	return &Peer{
		ID:          id,
		Online:      true,
		Fingerprint: opened.Fingerprint,
		Version:     opened.ProtocolVersion,
		LastSeen:    response.LastSeen,
		ExpiresAt:   response.ExpiresAt,
		Candidates:  opened.Candidates,
	}, nil
}

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

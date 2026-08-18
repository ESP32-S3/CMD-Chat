package phonebook

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/network"
)

func newIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sum := sha256.Sum256(public)
	id := "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
	return &identity.Identity{PrivateKey: private, PublicKey: public, ID: id}
}

// verifySignature re-implements the Worker's v2 check. If the Go client and the
// Worker ever disagree about the signing string, both test suites fail.
//
// Note what it CANNOT do, which is the point of the whole design: there is no ID
// in the request to check the key against. The directory verifies that the
// caller holds the write key for a handle, and learns nothing else.
func verifySignature(t *testing.T, r *http.Request, body []byte) string {
	t.Helper()

	var payload struct {
		Handle   string `json:"handle"`
		WriteKey string `json:"write_key"`
		IssuedAt int64  `json:"issued_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("server: malformed body: %v", err)
	}

	if len(payload.Handle) != HandleLength {
		t.Fatalf("server: handle %q is not %d characters", payload.Handle, HandleLength)
	}
	public, err := base64.StdEncoding.DecodeString(payload.WriteKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatalf("server: bad write key")
	}

	bodyHash := sha256.Sum256(body)
	message := strings.Join([]string{
		"cmd-chat-phonebook/v2",
		r.Method,
		r.URL.Path,
		strconv.FormatInt(payload.IssuedAt, 10),
		hex.EncodeToString(bodyHash[:]),
	}, "\n")

	signature, err := base64.StdEncoding.DecodeString(r.Header.Get(signatureHeader))
	if err != nil {
		t.Fatalf("server: signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, []byte(message), signature) {
		t.Fatalf("server: signature did not verify for %s %s", r.Method, r.URL.Path)
	}
	return payload.Handle
}

// sealedFor builds a directory response body for a peer, the way the host would.
func sealedFor(t *testing.T, id *identity.Identity, e entry) string {
	t.Helper()
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(id.ID, handle, e)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

type recorder struct {
	issuedAt []int64
	paths    []string
}

// newTestServer stands in for the Worker, enforcing the same auth rules.
func newTestServer(t *testing.T, rec *recorder, handler func(w http.ResponseWriter, r *http.Request, id string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.paths = append(rec.paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		var handle string
		if r.Method != http.MethodGet {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("server: read body: %v", err)
			}
			handle = verifySignature(t, r, body)

			var payload struct {
				IssuedAt int64 `json:"issued_at"`
			}
			_ = json.Unmarshal(body, &payload)
			rec.issuedAt = append(rec.issuedAt, payload.IssuedAt)
		}
		handler(w, r, handle)
	}))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestRegisterSealsEverythingAndSendsAHandle(t *testing.T) {
	rec := &recorder{}
	me := newIdentity(t)

	var received struct {
		Handle   string `json:"handle"`
		WriteKey string `json:"write_key"`
		Sealed   string `json:"sealed"`
	}
	var rawBody string

	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, handle string) {
		body, _ := io.ReadAll(strings.NewReader(rawBody))
		_ = body
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "handle": handle, "expires_at": 1, "ttl": 900, "heartbeat_interval": 300,
			"observed_ip": "203.0.113.7",
		})
	})
	defer server.Close()

	// Capture the exact bytes the client sent.
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		rawBody = string(data)
		if err := json.Unmarshal(data, &received); err != nil {
			t.Fatalf("body is not JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "handle": received.Handle, "ttl": 900, "heartbeat_interval": 300, "observed_ip": "203.0.113.7",
		})
	}))
	defer capture.Close()

	client := New(me, capture.URL)
	registration, err := client.Register(context.Background(), Announcement{
		Fingerprint:     strings.Repeat("A", 64),
		Candidates:      []Candidate{{Kind: KindHost, Transport: "tcp", Address: "192.168.1.42", Port: intPtr(38556), Priority: 100}},
		ProtocolVersion: 2,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registration.ObservedIP != "203.0.113.7" {
		t.Fatalf("observed IP = %q", registration.ObservedIP)
	}

	// The handle must be the blinded one, and the ID must appear nowhere.
	wantHandle, err := Handle(me.ID)
	if err != nil {
		t.Fatal(err)
	}
	if received.Handle != wantHandle {
		t.Fatalf("handle = %q, want %q", received.Handle, wantHandle)
	}
	for _, secret := range []string{me.ID, strings.TrimPrefix(me.ID, "cc-"), "192.168.1.42", "38556", strings.Repeat("a", 64)} {
		if strings.Contains(rawBody, secret) {
			t.Fatalf("%q was sent to the directory in the clear:\n%s", secret, rawBody)
		}
	}
	if strings.Contains(rawBody, base64.StdEncoding.EncodeToString(me.PublicKey)) {
		t.Fatal("the identity public key was sent to the directory")
	}

	// The write key must be the derived one, not the identity key.
	writeKey, err := WriteKey(me)
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString(writeKey.Public().(ed25519.PublicKey)); received.WriteKey != want {
		t.Fatalf("write_key = %q, want the derived key %q", received.WriteKey, want)
	}

	// And the sealed blob must open locally with the ID.
	opened, err := open(me.ID, wantHandle, received.Sealed)
	if err != nil {
		t.Fatalf("the client sealed something it cannot open: %v", err)
	}
	if len(opened.Candidates) != 1 || opened.Candidates[0].Address != "192.168.1.42" {
		t.Fatalf("sealed candidates = %+v", opened.Candidates)
	}
	if opened.ProtocolVersion != 2 {
		t.Fatalf("sealed protocol version = %d", opened.ProtocolVersion)
	}
}

func TestRegisterRefusesEmptyCandidateList(t *testing.T) {
	client := New(newIdentity(t), "http://127.0.0.1:1")
	if _, err := client.Register(context.Background(), Announcement{}); err == nil {
		t.Fatal("expected an error when registering with no candidates")
	}
}

func TestNeverTransmitsPrivateKey(t *testing.T) {
	rec := &recorder{}
	var bodies []string
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, id string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "ttl": 300})
	})
	defer server.Close()

	inner := server.Config.Handler
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		inner.ServeHTTP(w, r)
	})

	id := newIdentity(t)
	client := New(id, server.URL)
	port := 1234
	_, _ = client.Register(context.Background(), Announcement{
		Candidates: []Candidate{{Kind: KindHost, Transport: "tcp", Address: "10.0.0.1", Port: &port}},
	})
	_, _ = client.Heartbeat(context.Background())

	secret := base64.StdEncoding.EncodeToString(id.PrivateKey)
	seed := base64.StdEncoding.EncodeToString(id.PrivateKey.Seed())
	for _, body := range bodies {
		if strings.Contains(body, secret) || strings.Contains(body, seed) {
			t.Fatal("private key material appeared in a phonebook request body")
		}
		for _, banned := range []string{"private_key", "seed", "password"} {
			if strings.Contains(body, banned) {
				t.Fatalf("request body contains forbidden field %q", banned)
			}
		}

		// The blinded directory: neither the identity nor any address may reach
		// the service in readable form, on any call.
		if strings.Contains(body, id.ID) || strings.Contains(body, strings.TrimPrefix(id.ID, "cc-")) {
			t.Fatalf("the CMD-Chat ID reached the directory:\n%s", body)
		}
		if strings.Contains(body, base64.StdEncoding.EncodeToString(id.PublicKey)) {
			t.Fatalf("the identity public key reached the directory:\n%s", body)
		}
		if strings.Contains(body, "10.0.0.1") || strings.Contains(body, "\"candidates\"") {
			t.Fatalf("an address reached the directory in the clear:\n%s", body)
		}
	}
}

func TestIssuedAtIsStrictlyMonotonic(t *testing.T) {
	rec := &recorder{}
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, id string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "ttl": 300})
	})
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	for i := 0; i < 25; i++ {
		if _, err := client.Heartbeat(context.Background()); err != nil {
			t.Fatalf("Heartbeat %d: %v", i, err)
		}
	}
	for i := 1; i < len(rec.issuedAt); i++ {
		if rec.issuedAt[i] <= rec.issuedAt[i-1] {
			t.Fatalf("issued_at not strictly increasing at %d: %d then %d", i, rec.issuedAt[i-1], rec.issuedAt[i])
		}
	}
}

func TestLookupParsesPeer(t *testing.T) {
	target := newIdentity(t)
	handle, err := Handle(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	sealed := sealedFor(t, target, entry{
		ID:              target.ID,
		Fingerprint:     strings.Repeat("a", 64),
		ProtocolVersion: 2,
		Candidates: []Candidate{
			{Kind: KindServerReflexive, Transport: "udp", Address: "198.51.100.4", Port: intPtr(41234), Priority: 200},
			{Kind: KindHost, Transport: "tcp", Address: "192.168.0.7", Port: intPtr(38556), Priority: 100},
		},
	})

	var askedFor string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		askedFor = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "online": true, "sealed": sealed, "last_seen": 1700000000, "expires_at": 1700000900,
		})
	}))
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	peer, err := client.Lookup(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	// The ID must never appear in the request path; only the handle.
	if strings.Contains(askedFor, target.ID) || strings.Contains(askedFor, strings.TrimPrefix(target.ID, "cc-")) {
		t.Fatalf("the ID was sent to the directory in the path: %q", askedFor)
	}
	if !strings.Contains(askedFor, handle) {
		t.Fatalf("the request path %q does not carry the handle", askedFor)
	}

	if peer.ID != target.ID {
		t.Fatalf("peer.ID = %q", peer.ID)
	}
	if !peer.Online || len(peer.Candidates) != 2 {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	if tcp := peer.TCPEndpoints(); len(tcp) != 1 || tcp[0] != "192.168.0.7:38556" {
		t.Fatalf("TCPEndpoints = %v", tcp)
	}
	udp := peer.UDPEndpoints()
	if len(udp) != 1 || udp[0] != (network.Endpoint{Address: "198.51.100.4", Port: 41234}) {
		t.Fatalf("UDPEndpoints = %v", udp)
	}
	if peer.Version != 2 {
		t.Fatalf("peer.Version = %d", peer.Version)
	}
}

func TestLookupRejectsMalformedIDWithoutCallingServer(t *testing.T) {
	rec := &recorder{}
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	for _, bad := range []string{"", "nope", "cc-short", "cc-aaaaaaaaaaaaaaaa", "cc-AAAAAAAAAAAAAAA1", "../../etc/passwd"} {
		if _, err := client.Lookup(context.Background(), bad); err == nil {
			t.Fatalf("expected rejection of %q", bad)
		}
	}
	if len(rec.paths) != 0 {
		t.Fatalf("malformed IDs must not reach the network, got %v", rec.paths)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		code    string
		status  int
		wantErr error
	}{
		{"not_found", http.StatusNotFound, ErrNotFound},
		{"offline", http.StatusNotFound, ErrOffline},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			rec := &recorder{}
			server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, _ string) {
				writeJSON(w, tc.status, map[string]any{"ok": false, "error": tc.code, "message": "nope"})
			})
			defer server.Close()

			client := New(newIdentity(t), server.URL)
			_, err := client.Lookup(context.Background(), "cc-AAAAAAAAAAAAAAAA")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestHeartbeatLapsedRegistration(t *testing.T) {
	rec := &recorder{}
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, _ string) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_registered", "message": "gone"})
	})
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	if _, err := client.Heartbeat(context.Background()); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("got %v, want ErrNotRegistered", err)
	}
}

func TestAPIErrorSurfacesCode(t *testing.T) {
	rec := &recorder{}
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, _ string) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "rate_limited", "message": "slow down"})
	})
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	_, err := client.Heartbeat(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *APIError", err)
	}
	if apiErr.Code != "rate_limited" || apiErr.Status != http.StatusTooManyRequests {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
}

func TestUnregisterTargetsOwnHandleAndTolerates404(t *testing.T) {
	rec := &recorder{}
	id := newIdentity(t)
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, _ string) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found", "message": "gone"})
	})
	defer server.Close()

	client := New(id, server.URL)
	if err := client.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister should tolerate an absent entry, got %v", err)
	}

	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := "DELETE /v2/entry/" + handle
	if len(rec.paths) != 1 || rec.paths[0] != want {
		t.Fatalf("paths = %v, want %q", rec.paths, want)
	}
	// The ID must not be in the URL either. A path is the easiest thing in an
	// HTTP service to end up in an access log.
	if strings.Contains(rec.paths[0], id.ID) || strings.Contains(rec.paths[0], strings.TrimPrefix(id.ID, "cc-")) {
		t.Fatalf("the CMD-Chat ID appeared in the request path: %q", rec.paths[0])
	}
}

func TestKeepAliveStopsOnContextCancel(t *testing.T) {
	rec := &recorder{}
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, id string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "ttl": 300})
	})
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		client.KeepAlive(ctx, 10*time.Millisecond, nil, nil)
		close(done)
	}()

	time.Sleep(60 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("KeepAlive did not stop after context cancellation")
	}
	if len(rec.paths) == 0 {
		t.Fatal("KeepAlive never sent a heartbeat")
	}
}

func TestKeepAliveRenewsLapsedRegistration(t *testing.T) {
	rec := &recorder{}
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, _ string) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_registered", "message": "gone"})
	})
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	renewed := make(chan struct{}, 1)
	go client.KeepAlive(ctx, 10*time.Millisecond, func(context.Context) error {
		select {
		case renewed <- struct{}{}:
		default:
		}
		return nil
	}, nil)

	select {
	case <-renewed:
	case <-time.After(2 * time.Second):
		t.Fatal("KeepAlive did not call renew after a lapsed registration")
	}
}

func TestValidID(t *testing.T) {
	valid := []string{"cc-3XYJQWPNR5VUDYFF", "cc-AAAAAAAAAAAAAAAA", "cc-2345672345672345"}
	invalid := []string{"", "cc-", "cc-3XYJQWPNR5VUDYF", "cc-3XYJQWPNR5VUDYFFF", "xx-3XYJQWPNR5VUDYFF", "cc-3xyjqwpnr5vudyff", "cc-3XYJQWPNR5VUDY01"}

	for _, id := range valid {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, want true", id)
		}
	}
	for _, id := range invalid {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, want false", id)
		}
	}
}

// The identity package's own derivation must agree with ValidID, otherwise a
// real client could generate an ID the directory refuses.
func TestGeneratedIdentityIDIsAccepted(t *testing.T) {
	for i := 0; i < 50; i++ {
		if id := newIdentity(t); !ValidID(id.ID) {
			t.Fatalf("generated identity %q rejected by ValidID", id.ID)
		}
	}
}

func TestGatherCandidatesIncludesSTUNResult(t *testing.T) {
	candidates, err := GatherCandidates(38556, func() (*network.Endpoint, error) {
		return &network.Endpoint{Address: "203.0.113.9", Port: 51820}, nil
	})
	if err != nil {
		t.Fatalf("GatherCandidates: %v", err)
	}

	var reflexive *Candidate
	for i := range candidates {
		if candidates[i].Kind == KindServerReflexive {
			reflexive = &candidates[i]
		}
		if candidates[i].Port == nil {
			t.Fatalf("candidate %+v has no port", candidates[i])
		}
	}
	if reflexive == nil {
		t.Fatal("STUN result was not published as a server_reflexive candidate")
	}
	if reflexive.Transport != "udp" || reflexive.Address != "203.0.113.9" || *reflexive.Port != 51820 {
		t.Fatalf("unexpected reflexive candidate: %+v", reflexive)
	}
	if len(candidates) > 7 {
		t.Fatalf("candidate list of %d exceeds the directory limit", len(candidates))
	}

	for i := 1; i < len(candidates); i++ {
		if candidates[i-1].Priority < candidates[i].Priority {
			t.Fatal("candidates are not ordered best-first")
		}
	}
}

func TestGatherCandidatesSurvivesSTUNFailure(t *testing.T) {
	candidates, err := GatherCandidates(38556, func() (*network.Endpoint, error) {
		return nil, errors.New("no STUN server reachable")
	})
	if err == nil {
		t.Fatal("expected the STUN error to be reported")
	}
	for _, c := range candidates {
		if c.Kind == KindServerReflexive {
			t.Fatal("a failed STUN lookup must not produce a reflexive candidate")
		}
	}
}

func TestNewUsesDefaultBaseURLWhenEmpty(t *testing.T) {
	client := New(newIdentity(t), "   ")
	if client.BaseURL != DefaultBaseURL {
		t.Fatalf("BaseURL = %q, want %q", client.BaseURL, DefaultBaseURL)
	}
	if New(newIdentity(t), "https://example.test/").BaseURL != "https://example.test" {
		t.Fatal("trailing slash should be trimmed")
	}
}

// A directory that answers a lookup with a DIFFERENT peer must be refused.
//
// This is the first-contact defence. On a first connection the trust store has
// nothing to compare against, so a substituted entry here would be pinned and
// then faithfully authenticated: the caller really would be talking to the
// identity the directory handed it. The ID the user typed is the only value in
// this exchange that the directory does not control, so everything is checked
// against that.
// A directory that answers with a DIFFERENT peer's entry must be refused.
//
// Under v2 it cannot even produce one: the blob would have to open under the
// requested ID's key, and it has no way to make that happen. This asserts the
// failure is clean rather than confusing.
func TestLookupRefusesAnAnswerForADifferentPeer(t *testing.T) {
	wanted, substituted := newIdentity(t), newIdentity(t)

	// The directory serves the substituted peer's genuine, well-formed entry.
	sealed := sealedFor(t, substituted, entry{ID: substituted.ID, ProtocolVersion: 2})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "online": true, "sealed": sealed})
	}))
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	if _, err := client.Lookup(context.Background(), wanted.ID); !errors.Is(err, ErrDirectoryMismatch) {
		t.Fatalf("got %v, want ErrDirectoryMismatch", err)
	}
}

// A directory that returns a blob nobody can open is the same failure.
func TestLookupRefusesAnUnopenableEntry(t *testing.T) {
	wanted := newIdentity(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "online": true,
			"sealed": base64.StdEncoding.EncodeToString(make([]byte, 128)),
		})
	}))
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	if _, err := client.Lookup(context.Background(), wanted.ID); !errors.Is(err, ErrDirectoryMismatch) {
		t.Fatalf("got %v, want ErrDirectoryMismatch", err)
	}
}

// An entry sealed for the right peer but TAMPERED with must not be accepted, so
// a hostile directory cannot rewrite somebody's addresses.
func TestLookupRefusesATamperedEntry(t *testing.T) {
	target := newIdentity(t)
	sealed := sealedFor(t, target, entry{ID: target.ID, ProtocolVersion: 2})

	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "online": true, "sealed": tampered})
	}))
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	if _, err := client.Lookup(context.Background(), target.ID); !errors.Is(err, ErrDirectoryMismatch) {
		t.Fatalf("got %v, want ErrDirectoryMismatch", err)
	}
}

// A directory that has not been updated to the blinded endpoints must say so.
func TestLookupReportsAnOutdatedDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found", "message": "Unknown endpoint."})
	}))
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	_, err := client.Lookup(context.Background(), newIdentity(t).ID)
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrDirectoryOutdated) {
		t.Fatalf("got %v, want ErrNotFound or ErrDirectoryOutdated", err)
	}
}

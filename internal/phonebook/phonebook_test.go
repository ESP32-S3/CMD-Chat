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

// verifySignature re-implements the Worker's check. If the Go client and the
// Worker ever disagree about the signing string, these tests fail.
func verifySignature(t *testing.T, r *http.Request, body []byte) string {
	t.Helper()

	var payload struct {
		ID        string `json:"id"`
		PublicKey string `json:"public_key"`
		IssuedAt  int64  `json:"issued_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("server: malformed body: %v", err)
	}

	public, err := base64.StdEncoding.DecodeString(payload.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatalf("server: bad public key")
	}

	sum := sha256.Sum256(public)
	if want := "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]); want != payload.ID {
		t.Fatalf("server: id %q does not derive from public key (want %q)", payload.ID, want)
	}

	bodyHash := sha256.Sum256(body)
	message := strings.Join([]string{
		"cmd-chat-phonebook/v1",
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
	return payload.ID
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

		var id string
		if r.Method != http.MethodGet {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("server: read body: %v", err)
			}
			id = verifySignature(t, r, body)

			var payload struct {
				IssuedAt int64 `json:"issued_at"`
			}
			_ = json.Unmarshal(body, &payload)
			rec.issuedAt = append(rec.issuedAt, payload.IssuedAt)
		}
		handler(w, r, id)
	}))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestRegisterSignsRequestAndParsesResult(t *testing.T) {
	rec := &recorder{}
	var got struct {
		Candidates  []Candidate `json:"candidates"`
		Fingerprint string      `json:"session_fingerprint"`
		Version     string      `json:"client_version"`
	}

	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, id string) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok": true, "id": id, "expires_at": 1234, "ttl": 300, "heartbeat_interval": 100,
			"observed_ip": "203.0.113.7",
		})
	})
	defer server.Close()

	// Capture the body the client actually sent.
	inner := server.Config.Handler
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		inner.ServeHTTP(w, r)
	})

	client := New(newIdentity(t), server.URL)
	port := 38556
	result, err := client.Register(context.Background(), Announcement{
		Fingerprint: "AB" + strings.Repeat("cd", 31),
		Candidates: []Candidate{
			{Kind: KindHost, Transport: "tcp", Address: "192.168.1.5", Port: &port, Priority: 100},
		},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if result.TTL != 300 || result.ObservedIP != "203.0.113.7" {
		t.Fatalf("unexpected registration: %+v", result)
	}
	if result.HeartbeatIntervalDuration() != 100*time.Second {
		t.Fatalf("heartbeat interval = %v", result.HeartbeatIntervalDuration())
	}
	if len(got.Candidates) != 1 || got.Candidates[0].Address != "192.168.1.5" {
		t.Fatalf("candidates not sent verbatim: %+v", got.Candidates)
	}
	if got.Fingerprint != strings.ToLower("AB"+strings.Repeat("cd", 31)) {
		t.Fatalf("fingerprint should be lowercased, got %q", got.Fingerprint)
	}
	if got.Version == "" {
		t.Fatal("client_version was not sent")
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
	rec := &recorder{}
	server := newTestServer(t, rec, func(w http.ResponseWriter, r *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "id": "cc-AAAAAAAAAAAAAAAA", "online": true,
			"public_key":          "TEOZNabz0XpNzrl9Bhxexshebq/6hVlYT7GnWecAJLE=",
			"session_fingerprint": strings.Repeat("a", 64),
			"protocol_version":    1,
			"last_seen":           1700000000,
			"candidates": []map[string]any{
				{"kind": "server_reflexive", "transport": "udp", "address": "198.51.100.4", "port": 41234, "priority": 200},
				{"kind": "host", "transport": "tcp", "address": "192.168.0.7", "port": 38556, "priority": 100},
				{"kind": "server_reflexive_http", "transport": "udp", "address": "2001:db8::9", "port": nil, "priority": 0},
			},
		})
	})
	defer server.Close()

	client := New(newIdentity(t), server.URL)
	peer, err := client.Lookup(context.Background(), "cc-AAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !peer.Online || len(peer.Candidates) != 3 {
		t.Fatalf("unexpected peer: %+v", peer)
	}

	if tcp := peer.TCPEndpoints(); len(tcp) != 1 || tcp[0] != "192.168.0.7:38556" {
		t.Fatalf("TCPEndpoints = %v", tcp)
	}
	udp := peer.UDPEndpoints()
	if len(udp) != 1 || udp[0] != (network.Endpoint{Address: "198.51.100.4", Port: 41234}) {
		t.Fatalf("UDPEndpoints = %v", udp)
	}
	if observed := peer.ObservedIPs(); len(observed) != 1 || observed[0] != "2001:db8::9" {
		t.Fatalf("ObservedIPs = %v", observed)
	}
	if peer.Fingerprint != strings.Repeat("a", 64) {
		t.Fatal("session fingerprint not parsed; TLS pinning would break")
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

func TestUnregisterTargetsOwnIDAndTolerates404(t *testing.T) {
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
	want := "DELETE /register/" + id.ID
	if len(rec.paths) != 1 || rec.paths[0] != want {
		t.Fatalf("paths = %v, want %q", rec.paths, want)
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

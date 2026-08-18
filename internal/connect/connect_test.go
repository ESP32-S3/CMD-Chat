package connect

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/phonebook"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sum := sha256.Sum256(public)
	return &identity.Identity{
		PrivateKey: private,
		PublicKey:  public,
		ID:         "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]),
	}
}

// listener returns a TCP listener that accepts and holds connections.
func listener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	return ln
}

// blackhole is a routable-looking address that will not answer. Using a
// TEST-NET-1 address keeps the attempt off any real host.
const blackhole = "192.0.2.1:38556"

func TestDialFastestReturnsTheFirstAnswer(t *testing.T) {
	live := listener(t)
	conn, endpoint, err := dialFastest([]string{blackhole, live.Addr().String()}, 4*time.Second, func(string, ...any) {})
	if err != nil {
		t.Fatalf("dialFastest: %v", err)
	}
	defer conn.Close()
	if endpoint != live.Addr().String() {
		t.Fatalf("connected to %s, want %s", endpoint, live.Addr().String())
	}
}

func TestDialFastestFailsWithinBudget(t *testing.T) {
	start := time.Now()
	conn, _, err := dialFastest([]string{blackhole}, 1500*time.Millisecond, func(string, ...any) {})
	elapsed := time.Since(start)

	if err == nil {
		conn.Close()
		t.Fatal("expected the dial to fail")
	}
	// The point of the budget is that a dead candidate cannot hang the app.
	if elapsed > 4*time.Second {
		t.Fatalf("took %v, which exceeds the budget", elapsed)
	}
}

func TestDialFastestWithNoCandidates(t *testing.T) {
	if _, _, err := dialFastest(nil, time.Second, func(string, ...any) {}); err == nil {
		t.Fatal("expected an error with no candidates")
	}
}

func TestAddressFamily(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9:443":  "IPv4",
		"10.0.0.5:38556":   "IPv4, private",
		"192.168.1.7:1":    "IPv4, private",
		"[2001:db8::1]:80": "IPv6",
		"not-an-endpoint":  "direct",
	}
	for endpoint, want := range cases {
		if got := addressFamily(endpoint); got != want {
			t.Errorf("addressFamily(%q) = %q, want %q", endpoint, got, want)
		}
	}
}

func TestForceFromEnv(t *testing.T) {
	cases := map[string]Path{
		"":         "",
		"lan":      PathLAN,
		"DIRECT":   PathDirect,
		" relay":   PathRelay,
		"nonsense": "",
	}
	for value, want := range cases {
		t.Setenv("CMD_CHAT_TRANSPORT", value)
		if got := ForceFromEnv(); got != want {
			t.Errorf("ForceFromEnv() with %q = %q, want %q", value, got, want)
		}
	}
}

// fakePhonebook serves the subset of the directory API the strategy uses.
func fakePhonebook(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(respond))
	t.Cleanup(server.Close)
	return server.URL
}

func peerResponse(w http.ResponseWriter, id string, version int, endpoints []string) {
	candidates := make([]map[string]any, 0, len(endpoints))
	for _, endpoint := range endpoints {
		host, portStr, _ := net.SplitHostPort(endpoint)
		var port int
		_, _ = fmtSscan(portStr, &port)
		candidates = append(candidates, map[string]any{
			"kind": "host", "transport": "tcp", "address": host, "port": port, "priority": 100,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "id": id, "online": true,
		// Omitted on purpose: these fixtures address reachability, not identity,
		// and the directory client refuses a public key that does not derive the
		// ID it accompanies. internal/phonebook covers that check directly.
		"session_fingerprint": strings.Repeat("a", 64),
		"protocol_version":    version,
		"candidates":          candidates,
	})
}

func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(r-'0')
	}
	*out = n
	return 1, nil
}

func TestJoinPrefersDirectWhenACandidateAnswers(t *testing.T) {
	live := listener(t)
	target := testIdentity(t).ID

	url := fakePhonebook(t, func(w http.ResponseWriter, r *http.Request) {
		peerResponse(w, target, RelayProtocolVersion, []string{live.Addr().String()})
	})

	result, err := Join(target, Options{
		Identity:     testIdentity(t),
		PhonebookURL: url,
		RelayURL:     "http://127.0.0.1:1", // must not be reached
		LANTimeout:   50 * time.Millisecond,
		Force:        PathDirect,
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	defer result.Conn.Close()

	if result.Path != PathDirect {
		t.Fatalf("path = %q, want %q", result.Path, PathDirect)
	}
	if result.HostID != target {
		t.Fatalf("HostID = %q, want %q", result.HostID, target)
	}
	if result.Fingerprint == "" {
		t.Fatal("fingerprint was not carried through; pinning would be skipped")
	}
}

func TestJoinReportsUnreachableWhenDirectIsPinnedAndFails(t *testing.T) {
	target := testIdentity(t).ID
	url := fakePhonebook(t, func(w http.ResponseWriter, r *http.Request) {
		peerResponse(w, target, RelayProtocolVersion, []string{blackhole})
	})

	_, err := Join(target, Options{
		Identity:      testIdentity(t),
		PhonebookURL:  url,
		LANTimeout:    50 * time.Millisecond,
		DirectTimeout: time.Second,
		Force:         PathDirect,
	})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestJoinSkipsRelayForOlderPeers(t *testing.T) {
	target := testIdentity(t).ID
	url := fakePhonebook(t, func(w http.ResponseWriter, r *http.Request) {
		// protocol_version 1: a client with no relay support.
		peerResponse(w, target, 1, []string{blackhole})
	})

	var lines []string
	_, err := Join(target, Options{
		Identity:      testIdentity(t),
		PhonebookURL:  url,
		RelayURL:      "http://127.0.0.1:1",
		LANTimeout:    50 * time.Millisecond,
		DirectTimeout: time.Second,
		Log:           func(format string, args ...any) { lines = append(lines, format) },
	})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "does not support the relay") {
		t.Fatalf("expected the user to be told why, got:\n%s", joined)
	}
}

func TestJoinSurfacesOfflinePeer(t *testing.T) {
	target := testIdentity(t).ID
	url := fakePhonebook(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "offline", "message": "stale"})
	})

	_, err := Join(target, Options{
		Identity:     testIdentity(t),
		PhonebookURL: url,
		LANTimeout:   50 * time.Millisecond,
	})
	if !errors.Is(err, phonebook.ErrOffline) {
		t.Fatalf("got %v, want phonebook.ErrOffline", err)
	}
}

// Progress lines are shown to users, so they must not leak addresses.
func TestLogLinesDoNotContainRawAddresses(t *testing.T) {
	live := listener(t)
	target := testIdentity(t).ID
	url := fakePhonebook(t, func(w http.ResponseWriter, r *http.Request) {
		peerResponse(w, target, RelayProtocolVersion, []string{live.Addr().String()})
	})

	var lines []string
	result, err := Join(target, Options{
		Identity:     testIdentity(t),
		PhonebookURL: url,
		LANTimeout:   50 * time.Millisecond,
		Force:        PathDirect,
		Log:          func(format string, args ...any) { lines = append(lines, format) },
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	defer result.Conn.Close()

	host, _, _ := net.SplitHostPort(live.Addr().String())
	for _, line := range lines {
		if strings.Contains(line, host) {
			t.Fatalf("progress line leaked an address: %q", line)
		}
	}
}

// The identity that gets pinned must be the one the USER typed, never one the
// network supplied.
//
// This is what makes a first connection safe. A CMD-Chat ID is a hash of a
// public key, so typing a friend's ID already commits to their exact key — but
// only if that typed value is what the handshake goes on to require. If the
// pinned ID came from the directory's answer instead, a hostile directory could
// substitute its own peer, and on a first contact there would be nothing in the
// trust store to catch it: the caller really would be talking to the identity it
// was handed.
func TestJoinPinsTheIDTheCallerAskedFor(t *testing.T) {
	live := listener(t)
	target := testIdentity(t).ID

	// The directory answers correctly here; the point is what Join carries
	// forward, not whether the directory misbehaved.
	url := fakePhonebook(t, func(w http.ResponseWriter, r *http.Request) {
		peerResponse(w, target, RelayProtocolVersion, []string{live.Addr().String()})
	})

	result, err := Join(target, Options{
		Identity:     testIdentity(t),
		PhonebookURL: url,
		RelayURL:     "http://127.0.0.1:1",
		LANTimeout:   50 * time.Millisecond,
		Force:        PathDirect,
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	defer result.Conn.Close()

	if result.HostID != target {
		t.Fatalf("HostID = %q, want the caller's target %q", result.HostID, target)
	}
}

// A directory that answers with a different peer must abort the whole strategy,
// not fall through to the relay with a substituted identity.
func TestJoinAbortsWhenTheDirectoryAnswersWithADifferentPeer(t *testing.T) {
	wanted := testIdentity(t).ID
	substituted := testIdentity(t).ID

	url := fakePhonebook(t, func(w http.ResponseWriter, r *http.Request) {
		peerResponse(w, substituted, RelayProtocolVersion, []string{"127.0.0.1:1"})
	})

	_, err := Join(wanted, Options{
		Identity:     testIdentity(t),
		PhonebookURL: url,
		RelayURL:     "http://127.0.0.1:1",
		LANTimeout:   50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Join accepted a directory answer for a different peer")
	}
	if !errors.Is(err, phonebook.ErrDirectoryMismatch) {
		t.Fatalf("got %v, want ErrDirectoryMismatch", err)
	}
}

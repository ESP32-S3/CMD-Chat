package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

func unitIdentity(t *testing.T) *identity.Identity {
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

func TestWebsocketURL(t *testing.T) {
	cases := map[string]string{
		"https://relay.example":  "wss://relay.example/relay/cc-AAAAAAAAAAAAAAAA",
		"https://relay.example/": "wss://relay.example/relay/cc-AAAAAAAAAAAAAAAA",
		"http://127.0.0.1:8788":  "ws://127.0.0.1:8788/relay/cc-AAAAAAAAAAAAAAAA",
		"wss://already.example":  "wss://already.example/relay/cc-AAAAAAAAAAAAAAAA",
	}
	for base, want := range cases {
		if got := websocketURL(base, "cc-AAAAAAAAAAAAAAAA"); got != want {
			t.Errorf("websocketURL(%q) = %q, want %q", base, got, want)
		}
	}
}

// The relay verifies this signature, so the client must produce exactly the
// string the Worker reconstructs: prefix, role, session, id, issued_at.
func TestAuthHeadersProduceAVerifiableSignature(t *testing.T) {
	ident := unitIdentity(t)
	headers := authHeaders(ident, "guest", "cc-BBBBBBBBBBBBBBBB")

	if headers.Get("X-CmdChat-Role") != "guest" {
		t.Fatalf("role = %q", headers.Get("X-CmdChat-Role"))
	}
	if headers.Get("X-CmdChat-Id") != ident.ID {
		t.Fatalf("id = %q, want %q", headers.Get("X-CmdChat-Id"), ident.ID)
	}

	publicKey, err := base64.StdEncoding.DecodeString(headers.Get("X-CmdChat-PublicKey"))
	if err != nil {
		t.Fatalf("public key is not base64: %v", err)
	}
	// The ID must be derivable from the advertised key, or the relay rejects it.
	sum := sha256.Sum256(publicKey)
	derived := "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
	if derived != ident.ID {
		t.Fatalf("advertised key derives %q, want %q", derived, ident.ID)
	}

	issuedAt, err := strconv.ParseInt(headers.Get("X-CmdChat-IssuedAt"), 10, 64)
	if err != nil {
		t.Fatalf("issued_at is not an integer: %v", err)
	}

	signature, err := base64.StdEncoding.DecodeString(headers.Get("X-CmdChat-Signature"))
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}

	message := strings.Join([]string{signingPrefix, "guest", "cc-BBBBBBBBBBBBBBBB", ident.ID, strconv.FormatInt(issuedAt, 10)}, "\n")
	if !ed25519.Verify(ident.PublicKey, []byte(message), signature) {
		t.Fatal("signature does not verify against the expected signing string")
	}
}

// Binding role and session into the signature is what stops a captured guest
// signature being replayed to claim a host slot, or to join another session.
func TestSignatureIsBoundToRoleAndSession(t *testing.T) {
	ident := unitIdentity(t)
	guest := authHeaders(ident, "guest", "cc-BBBBBBBBBBBBBBBB").Get("X-CmdChat-Signature")
	host := authHeaders(ident, "host", "cc-BBBBBBBBBBBBBBBB").Get("X-CmdChat-Signature")
	other := authHeaders(ident, "guest", "cc-CCCCCCCCCCCCCCCC").Get("X-CmdChat-Signature")

	if guest == host {
		t.Fatal("role is not bound into the signature")
	}
	if guest == other {
		t.Fatal("session is not bound into the signature")
	}
}

func TestNeverTransmitsPrivateKey(t *testing.T) {
	ident := unitIdentity(t)
	headers := authHeaders(ident, "host", ident.ID)

	secret := base64.StdEncoding.EncodeToString(ident.PrivateKey)
	seed := base64.StdEncoding.EncodeToString(ident.PrivateKey.Seed())
	for name, values := range headers {
		for _, v := range values {
			if strings.Contains(v, secret) || strings.Contains(v, seed) {
				t.Fatalf("header %s carries private key material", name)
			}
		}
	}
}

func TestTranslateDialError(t *testing.T) {
	cases := []struct {
		body string
		want error
	}{
		{`{"ok":false,"error":"no_host","message":"nope"}`, ErrNoHost},
		{`{"ok":false,"error":"session_busy","message":"busy"}`, ErrSessionBusy},
	}
	for _, tc := range cases {
		err := translateDialError(&HTTPError{Status: 409, Body: tc.body})
		if !errors.Is(err, tc.want) {
			t.Errorf("body %s translated to %v, want %v", tc.body, err, tc.want)
		}
	}

	// Anything unrecognised must pass through rather than be misreported.
	original := &HTTPError{Status: 401, Body: `{"error":"invalid_signature"}`}
	if got := translateDialError(original); !errors.Is(got, original) {
		t.Fatalf("unexpected translation: %v", got)
	}
}

func TestBaseURLHonoursEnvironment(t *testing.T) {
	t.Setenv(BaseURLEnv, "")
	if BaseURL() != DefaultBaseURL {
		t.Fatalf("BaseURL() = %q, want the default", BaseURL())
	}
	t.Setenv(BaseURLEnv, "  http://127.0.0.1:8788  ")
	if BaseURL() != "http://127.0.0.1:8788" {
		t.Fatalf("BaseURL() = %q, want the override trimmed", BaseURL())
	}
}

package phonebook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNicknameNeverReachesThePhonebook is the privacy boundary for nicknames.
//
// A nickname is a person's name for themselves. The phonebook is a public
// directory of reachable addresses, stored in D1; putting a nickname in it would
// turn a list of IDs into a list of people, and would leak the name to anyone
// who can look up the ID rather than only to the people in the chat.
//
// The nickname is therefore carried inside the authenticated chat session and
// nowhere else. This test asserts the negative directly: it registers with a
// distinctive nickname set on the identity's display name and fails if that
// string appears anywhere in the request the client actually sends.
func TestNicknameNeverReachesThePhonebook(t *testing.T) {
	const nickname = "NICKNAME-CANARY-9174"

	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		bodies = append(bodies, string(body))
		for name, values := range r.Header {
			for _, v := range values {
				bodies = append(bodies, name+": "+v)
			}
		}
		bodies = append(bodies, r.URL.String())

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "expires_at": 1234, "ttl": 300, "heartbeat_interval": 100,
			"observed_ip": "203.0.113.7",
		})
	}))
	defer server.Close()

	client := New(newIdentity(t), server.URL)

	announcement := Announcement{
		Fingerprint: strings.Repeat("ab", 32),
		Candidates: []Candidate{{
			Kind: KindHost, Transport: "tcp", Address: "192.0.2.1", Port: intPtr(38556), Priority: 100,
		}},
		ProtocolVersion: 2,
	}

	if _, err := client.Register(context.Background(), announcement); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if len(bodies) == 0 {
		t.Fatal("the test server observed no request")
	}
	for _, chunk := range bodies {
		if strings.Contains(chunk, nickname) {
			t.Fatalf("the nickname reached the phonebook: %q", chunk)
		}
	}

	// The announcement type must not even have somewhere to put one, so a
	// future change cannot start publishing it by accident.
	encoded, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"nickname", "\"name\"", "display_name"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("Announcement carries a %s field: %s", forbidden, encoded)
		}
	}
}

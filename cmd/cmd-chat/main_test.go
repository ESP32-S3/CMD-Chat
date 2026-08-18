package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ESP32-S3/CMD-Chat/internal/e2ee"
	"io"
	"os"
	"strings"
	"testing"
)

// TestArgsAfterHandlesShortArgv is the regression test for the crash that closed
// the terminal window.
//
// The menu called into the host subcommand with os.Args holding nothing but the
// executable name, and os.Args[2:] panicked before a single socket was opened.
// Debug mode passed --debug-child, which made os.Args long enough for the slice
// to be legal, so the crash only ever happened in the one mode nobody could see
// a log from.
func TestArgsAfterHandlesShortArgv(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want int
	}{
		{"double-clicked launcher, no arguments", []string{"cmd-chat"}, 0},
		{"debug child", []string{"cmd-chat", "--debug-child"}, 0},
		{"bare subcommand", []string{"cmd-chat", "host"}, 0},
		{"subcommand with flags", []string{"cmd-chat", "host", "--port", "1234"}, 2},
	}

	original := os.Args
	t.Cleanup(func() { os.Args = original })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.argv
			got := argsAfter(2)
			if len(got) != tc.want {
				t.Fatalf("argsAfter(2) returned %d argument(s), want %d", len(got), tc.want)
			}
		})
	}
}

// TestFlagParseDoesNotExit guards the other way the window used to vanish: the
// flag sets used flag.ExitOnError, so a mistyped flag terminated the process
// rather than the subcommand.
func TestFlagParseDoesNotExit(t *testing.T) {
	fs := newFlags("host")
	fs.SetOutput(os.NewFile(0, os.DevNull))
	fs.Int("port", tcpPort, "TCP listen port")
	if err := fs.Parse([]string{"--nonsense"}); err == nil {
		t.Fatal("parsing an unknown flag returned no error")
	}
}

// TestIsAddrInUseRecognisesBothPlatformWordings keeps the "another CMD-Chat is
// open" message from being shown as a firewall problem, and vice versa.
func TestIsAddrInUseRecognisesBothPlatformWordings(t *testing.T) {
	inUse := []error{
		errorString("listen tcp :38556: bind: address already in use"),
		errorString("listen tcp :38556: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted."),
	}
	for _, err := range inUse {
		if !isAddrInUse(err) {
			t.Fatalf("isAddrInUse(%q) = false, want true", err)
		}
	}

	blocked := []error{
		nil,
		errorString("listen tcp :38556: bind: permission denied"),
		errorString("listen tcp :38556: bind: An attempt was made to access a socket in a way forbidden by its access permissions."),
	}
	for _, err := range blocked {
		if isAddrInUse(err) {
			t.Fatalf("isAddrInUse(%v) = true, want false", err)
		}
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

// captureStdout runs f and returns whatever it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	f()
	_ = w.Close()
	os.Stdout = original
	return <-done
}

// A refused connection has to explain itself in terms the person can act on.
//
// These are the four outcomes a user can actually hit, and each needs different
// advice: update your software, check with your friend out of band, or stop.
// Getting the classification wrong sends someone hunting for an attacker when
// their friend just needs to update — or worse, the other way round.
func TestHandshakeFailuresAreExplained(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		expect []string
		reject []string
	}{
		{
			name:   "peer running an old version",
			err:    fmt.Errorf("dial: %w", e2ee.ErrLegacyPeer),
			expect: []string{"older CMD-Chat", "releases/latest"},
			reject: []string{"impersonate"},
		},
		{
			name:   "peer hung up on the handshake",
			err:    e2ee.ErrPeerClosedHandshake,
			expect: []string{"older CMD-Chat", "releases/latest"},
			reject: []string{"impersonate"},
		},
		{
			name:   "identity key changed",
			err:    errors.New("host identity authentication failed: auth: this ID previously used a different identity key"),
			expect: []string{"different identity key", "cmd-chat forget", "not this chat"},
		},
		{
			name:   "certificate fingerprint mismatch",
			err:    errors.New("host certificate fingerprint mismatch"),
			expect: []string{"intercepting"},
		},
		{
			name:   "wrong peer answered",
			err:    errors.New("host identity authentication failed: identity mismatch, expected cc-A but the peer proved cc-B"),
			expect: []string{"not the ID you asked for", "Do not proceed"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() { reportHandshakeFailure(tc.err) })
			if strings.TrimSpace(out) == "" {
				t.Fatal("a refused connection printed nothing at all")
			}
			for _, want := range tc.expect {
				if !strings.Contains(out, want) {
					t.Errorf("the explanation does not mention %q:\n%s", want, out)
				}
			}
			for _, unwanted := range tc.reject {
				if strings.Contains(out, unwanted) {
					t.Errorf("the explanation wrongly mentions %q:\n%s", unwanted, out)
				}
			}
		})
	}
}

// An unrecognised failure must still say something, rather than failing silently.
func TestUnknownHandshakeFailureStillReports(t *testing.T) {
	out := captureStdout(t, func() { reportHandshakeFailure(errors.New("some new failure mode")) })
	if !strings.Contains(out, "some new failure mode") {
		t.Fatalf("an unclassified failure lost its reason:\n%s", out)
	}
}

package main

import (
	"os"
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

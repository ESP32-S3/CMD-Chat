package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolate points os.UserConfigDir at a temp directory and clears the cached
// profile, so a test never reads or writes the real user profile.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)         // Windows
	t.Setenv("XDG_CONFIG_HOME", dir) // Linux
	t.Setenv("HOME", dir)            // macOS / fallback
	mu.Lock()
	loaded = nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		loaded = nil
		mu.Unlock()
	})
	return dir
}

func TestNicknameRoundTrips(t *testing.T) {
	isolate(t)

	if err := SetNickname("Alex"); err != nil {
		t.Fatalf("SetNickname: %v", err)
	}
	if got := Name(); got != "Alex" {
		t.Fatalf("Name() = %q, want Alex", got)
	}

	// A fresh read from disk must agree with what was just written.
	mu.Lock()
	loaded = nil
	mu.Unlock()
	if got := Name(); got != "Alex" {
		t.Fatalf("Name() after reload = %q, want Alex", got)
	}
}

func TestEmptyNicknameFallsBackToAccountName(t *testing.T) {
	isolate(t)
	t.Setenv("USERNAME", "winuser")

	if got := Name(); got != "winuser" {
		t.Fatalf("Name() with no nickname = %q, want the account name", got)
	}
	if err := SetNickname("Alex"); err != nil {
		t.Fatalf("SetNickname: %v", err)
	}
	if err := SetNickname("   "); err != nil {
		t.Fatalf("SetNickname(blank): %v", err)
	}
	if got := Name(); got != "winuser" {
		t.Fatalf("clearing the nickname gave %q, want the account name back", got)
	}
}

// TestCleanNicknameStripsTerminalControl is the one that matters for safety: a
// nickname is printed next to every message its owner sends, so a peer must not
// be able to smuggle escape sequences onto someone else's screen.
func TestCleanNicknameStripsTerminalControl(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Alex", "Alex"},
		{"  Alex  ", "Alex"},
		{"Alex\r\n> ", "Alex >"},
		{"a\x1b[31mred", "a[31mred"},
		{"a\x00b", "ab"},
		{"a\tb", "a b"},
		{"spaced      out", "spaced out"},
		{"", ""},
		{"\x1b\x07\x00", ""},
	}
	for _, tc := range cases {
		if got := CleanNickname(tc.in); got != tc.want {
			t.Errorf("CleanNickname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// No control characters survive, whatever the input.
	for _, r := range CleanNickname("x\x1b[2J\x07\r\ny") {
		if r == 0x7f || (r < 0x20 && r != ' ') {
			t.Errorf("control character %q survived cleaning", r)
		}
	}
}

func TestCleanNicknameBoundsLength(t *testing.T) {
	long := strings.Repeat("n", MaxNicknameLength*3)
	if got := CleanNickname(long); len(got) != MaxNicknameLength {
		t.Fatalf("length = %d, want %d", len(got), MaxNicknameLength)
	}

	// Truncation must not split a multi-byte rune into invalid UTF-8.
	wide := strings.Repeat("é", MaxNicknameLength)
	got := CleanNickname(wide)
	if len(got) > MaxNicknameLength {
		t.Fatalf("length = %d, want <= %d", len(got), MaxNicknameLength)
	}
	if !isValidUTF8(got) {
		t.Fatalf("truncation produced invalid UTF-8: %q", got)
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}

func TestGroupChatDefaultsToEnabled(t *testing.T) {
	isolate(t)

	if !GroupChatEnabled() {
		t.Fatal("group chat defaulted to off; a host silently refusing a second guest looks offline")
	}
	if err := SetGroupChatEnabled(false); err != nil {
		t.Fatalf("SetGroupChatEnabled: %v", err)
	}
	if GroupChatEnabled() {
		t.Fatal("group chat stayed on after being turned off")
	}

	mu.Lock()
	loaded = nil
	mu.Unlock()
	if GroupChatEnabled() {
		t.Fatal("the off setting did not survive a reload")
	}

	if err := SetGroupChatEnabled(true); err != nil {
		t.Fatalf("SetGroupChatEnabled: %v", err)
	}
	if !GroupChatEnabled() {
		t.Fatal("group chat stayed off after being turned back on")
	}
}

// TestNicknameAndGroupSettingAreIndependent guards against one setting clearing
// the other, which is easy to do when both live in one file.
func TestNicknameAndGroupSettingAreIndependent(t *testing.T) {
	isolate(t)

	if err := SetNickname("Alex"); err != nil {
		t.Fatalf("SetNickname: %v", err)
	}
	if err := SetGroupChatEnabled(false); err != nil {
		t.Fatalf("SetGroupChatEnabled: %v", err)
	}
	if got := Name(); got != "Alex" {
		t.Fatalf("nickname became %q after changing the group setting", got)
	}

	if err := SetNickname("Sam"); err != nil {
		t.Fatalf("SetNickname: %v", err)
	}
	if GroupChatEnabled() {
		t.Fatal("group setting reverted after changing the nickname")
	}
}

// TestProfileIsWrittenBesideTheIdentity keeps the nickname on this machine, in
// the directory that already holds machine-local secrets.
func TestProfileIsWrittenBesideTheIdentity(t *testing.T) {
	dir := isolate(t)

	if err := SetNickname("Alex"); err != nil {
		t.Fatalf("SetNickname: %v", err)
	}
	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if !strings.HasPrefix(path, dir) {
		t.Fatalf("profile written to %q, outside the config dir %q", path, dir)
	}
	if filepath.Base(path) != "profile.json" {
		t.Fatalf("profile file is %q, want profile.json", filepath.Base(path))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("profile file not written: %v", err)
	}
}

func TestCorruptProfileIsIgnored(t *testing.T) {
	isolate(t)
	t.Setenv("USERNAME", "winuser")

	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := Name(); got != "winuser" {
		t.Fatalf("Name() with a corrupt profile = %q, want the account name", got)
	}
	if !GroupChatEnabled() {
		t.Fatal("a corrupt profile turned group chat off")
	}
}

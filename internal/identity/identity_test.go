package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// isolateConfigDir redirects os.UserConfigDir at a temp directory, so the test
// never reads or writes the real identity on the machine running it.
//
// Each platform reads a different variable: %AppData% on Windows,
// $XDG_CONFIG_HOME (falling back to $HOME) on Linux, and $HOME on macOS.
// Setting only XDG_CONFIG_HOME silently did nothing on Windows, which is why
// this test used to fail there.
func isolateConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)

	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	return configDir
}

func TestLoadOrCreateStable(t *testing.T) {
	configDir := isolateConfigDir(t)

	a, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}

	if a.ID != b.ID {
		t.Fatalf("identity changed: %q != %q", a.ID, b.ID)
	}
	if a.PublicKey != nil && b.PublicKey != nil && string(a.PublicKey) != string(b.PublicKey) {
		t.Fatal("public key changed")
	}

	// Derive the expected location the same way the package does, rather than
	// assuming a layout, so this holds on Windows, Linux and macOS alike.
	if _, err := os.Stat(filepath.Join(configDir, "cmd-chat", "identity.json")); err != nil {
		t.Fatal(err)
	}
}

// The ID must be a deterministic function of the public key, since every
// authorisation decision in CMD-Chat depends on that.
func TestDeriveIDMatchesStoredID(t *testing.T) {
	isolateConfigDir(t)

	id, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if got := DeriveID(id.PublicKey); got != id.ID {
		t.Fatalf("DeriveID = %q, stored ID = %q", got, id.ID)
	}
	if !Valid(id) {
		t.Fatal("freshly created identity does not validate")
	}
}

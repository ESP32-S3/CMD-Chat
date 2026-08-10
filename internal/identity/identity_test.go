package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateStable(t *testing.T) {
	root := t.TempDir()
	old := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", old)
	_ = os.Setenv("XDG_CONFIG_HOME", root)
	a, err := LoadOrCreate(); if err != nil { t.Fatal(err) }
	b, err := LoadOrCreate(); if err != nil { t.Fatal(err) }
	if a.ID != b.ID { t.Fatalf("identity changed: %q != %q", a.ID, b.ID) }
	if a.PublicKey != nil && b.PublicKey != nil && string(a.PublicKey) != string(b.PublicKey) { t.Fatal("public key changed") }
	if _, err := os.Stat(filepath.Join(root, "cmd-chat", "identity.json")); err != nil { t.Fatal(err) }
}

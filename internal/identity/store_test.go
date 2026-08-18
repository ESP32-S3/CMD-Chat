package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// storedFile reads the raw on-disk record.
func storedFile(t *testing.T) storedIdentity {
	t.Helper()
	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	var stored storedIdentity
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	return stored
}

// rawFile is the identity file's bytes, for checking that a private key is not
// sitting in them.
func rawFile(t *testing.T) []byte {
	t.Helper()
	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	return data
}

// The default on the platform this is running on must be the strongest one
// available without asking the user for anything.
func TestDefaultProtectionIsTheBestAvailable(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "")

	id, err := LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	stored := storedFile(t)
	if runtime.GOOS == "windows" {
		if stored.Protection != ProtectionDPAPI {
			t.Fatalf("on Windows the key was stored with protection %q, want %q", stored.Protection, ProtectionDPAPI)
		}
		// The seed must not be recoverable from the file itself.
		if bytes.Contains(rawFile(t), []byte(base64.StdEncoding.EncodeToString(id.PrivateKey.Seed()))) {
			t.Fatal("the raw private key seed appears in the identity file")
		}
		if stored.PrivateKey != "" {
			t.Fatal("a cleartext private key was written alongside the sealed one")
		}
	} else if stored.Protection != ProtectionNone {
		t.Fatalf("protection is %q, want %q on this platform", stored.Protection, ProtectionNone)
	}

	// Whatever the mode, it has to load back.
	again, err := LoadOrCreate()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.ID != id.ID || !bytes.Equal(again.PrivateKey, id.PrivateKey) {
		t.Fatal("the identity did not survive a round trip through storage")
	}
}

// Passphrase protection works on every platform and is the strongest mode.
func TestPassphraseProtection(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "correct horse battery staple")

	id, err := LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	stored := storedFile(t)
	if stored.Protection != ProtectionPassphrase {
		t.Fatalf("protection = %q, want %q", stored.Protection, ProtectionPassphrase)
	}
	if stored.PrivateKey != "" {
		t.Fatal("a cleartext private key was written despite a passphrase being set")
	}
	if stored.Salt == "" || stored.Sealed == "" {
		t.Fatal("the sealed record is missing its salt or ciphertext")
	}
	raw := rawFile(t)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(id.PrivateKey.Seed()))) {
		t.Fatal("the private key seed appears in the file in the clear")
	}
	if bytes.Contains(raw, []byte("correct horse battery staple")) {
		t.Fatal("the passphrase itself was written to disk")
	}

	// The right passphrase opens it.
	reloaded, err := Load()
	if err != nil {
		t.Fatalf("reload with the passphrase: %v", err)
	}
	if reloaded.ID != id.ID {
		t.Fatal("the identity changed across a sealed round trip")
	}

	// The wrong one does not, and says so rather than silently minting a new ID.
	t.Setenv(PassphraseEnv, "not the passphrase")
	if _, err := Load(); err == nil {
		t.Fatal("the wrong passphrase opened the identity")
	}

	// No passphrase at all also fails closed.
	t.Setenv(PassphraseEnv, "")
	if _, err := Load(); err == nil {
		t.Fatal("a sealed identity loaded with no passphrase")
	}
}

// Tampering with the sealed blob must be detected, not silently tolerated.
func TestTamperedSealedIdentityIsRejected(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "a passphrase")

	if _, err := LoadOrCreate(); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	stored := storedFile(t)
	sealed, err := base64.StdEncoding.DecodeString(stored.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0x01
	stored.Sealed = base64.StdEncoding.EncodeToString(sealed)

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(); err == nil {
		t.Fatal("a tampered sealed identity was accepted")
	}
}

// A version 1 file — the old cleartext layout — must still load, and must be
// upgraded in place to whatever protection is now available.
func TestLegacyPlaintextIdentityIsUpgraded(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "upgrade me")

	original, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Write the version 1 layout by hand.
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]string{
		"private_key": base64.StdEncoding.EncodeToString(original.PrivateKey),
		"public_key":  base64.StdEncoding.EncodeToString(original.PublicKey),
		"id":          original.ID,
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("a version 1 identity did not load: %v", err)
	}
	// The user's ID must NOT change. Regenerating it would break every peer that
	// had already pinned it.
	if loaded.ID != original.ID {
		t.Fatalf("the ID changed on upgrade: %q became %q", original.ID, loaded.ID)
	}

	stored := storedFile(t)
	if stored.Version != storeVersion {
		t.Fatalf("the file was not upgraded: version %d", stored.Version)
	}
	if stored.Protection != ProtectionPassphrase {
		t.Fatalf("after upgrade protection is %q", stored.Protection)
	}
	if stored.PrivateKey != "" {
		t.Fatal("the cleartext private key survived the upgrade")
	}
}

// An unknown protection mode — a file written by a newer build — must fail
// closed rather than being discarded and replaced with a new identity.
func TestUnknownProtectionFailsClosed(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "")

	id, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	stored := storedFile(t)
	stored.Protection = "some-future-hsm"
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(); err == nil {
		t.Fatal("an unknown protection mode was loaded anyway")
	}
	_ = id
}

// The file must never be group- or world-readable on a POSIX system.
func TestIdentityFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows; DPAPI is the protection there")
	}
	configDir := isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "")

	if _, err := LoadOrCreate(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(configDir, "cmd-chat", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("identity.json is mode %o; it must not be readable by anyone else", mode)
	}

	dir, err := os.Stat(filepath.Join(configDir, "cmd-chat"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dir.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("the cmd-chat directory is mode %o", mode)
	}
}

// Save must be atomic: a crash mid-write must not be able to leave a truncated
// file that LoadOrCreate would discard, silently changing the user's ID.
func TestSaveLeavesNoPartialFile(t *testing.T) {
	configDir := isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "")

	id, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := Save(id); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(configDir, "cmd-chat"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("a temporary file was left behind: %s", e.Name())
		}
	}
}

// An inconsistent identity must never be written.
func TestSaveRefusesAnInconsistentIdentity(t *testing.T) {
	isolateConfigDir(t)

	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	id.ID = "cc-SOMETHINGELSE"
	if err := Save(id); err == nil {
		t.Fatal("an identity whose ID does not match its key was stored")
	}
}

// DeriveID must be stable and must actually depend on the whole key.
func TestDeriveIDDependsOnTheKey(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatal("two identities collided")
	}
	if DeriveID(a.PublicKey) != a.ID {
		t.Fatal("DeriveID is not stable")
	}

	// Flipping one bit anywhere in the key must change the ID.
	for i := range a.PublicKey {
		altered := append([]byte(nil), a.PublicKey...)
		altered[i] ^= 0x01
		if DeriveID(altered) == a.ID {
			t.Fatalf("flipping bit 0 of byte %d did not change the ID", i)
		}
	}
}

// An identity file that exists but cannot be opened must NOT be replaced.
//
// A CMD-Chat ID is the name every peer has pinned. Quietly generating a new one
// because the stored key would not unseal would change the user's ID and make
// every friend they have see exactly what an impersonation attempt looks like.
func TestLoadOrCreateRefusesToReplaceAnUnreadableIdentity(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "the right passphrase")

	original, err := LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// The wrong passphrase must be an error, not a new identity.
	t.Setenv(PassphraseEnv, "the wrong passphrase")
	if replaced, err := LoadOrCreate(); err == nil {
		t.Fatalf("a wrong passphrase silently minted a new identity %s, replacing %s", replaced.ID, original.ID)
	}

	// No passphrase at all: same.
	t.Setenv(PassphraseEnv, "")
	if replaced, err := LoadOrCreate(); err == nil {
		t.Fatalf("a missing passphrase silently minted a new identity %s", replaced.ID)
	}

	// And the original must still be there, untouched, once the passphrase is
	// right again.
	t.Setenv(PassphraseEnv, "the right passphrase")
	recovered, err := LoadOrCreate()
	if err != nil {
		t.Fatalf("the identity did not survive the failed attempts: %v", err)
	}
	if recovered.ID != original.ID {
		t.Fatalf("the ID changed: %s became %s", original.ID, recovered.ID)
	}
}

// An unknown protection mode must not be treated as "start over" either.
func TestLoadOrCreateRefusesAnUnknownProtectionMode(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "")

	original, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}

	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	stored := storedFile(t)
	stored.Protection = "future-hardware-token"
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if replaced, err := LoadOrCreate(); err == nil {
		t.Fatalf("an unknown protection mode produced a new identity %s, replacing %s", replaced.ID, original.ID)
	}
}

// A first run, with no file at all, must still work.
func TestLoadOrCreateCreatesOnFirstRun(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(PassphraseEnv, "")

	id, err := LoadOrCreate()
	if err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	if !Valid(id) {
		t.Fatal("the freshly created identity does not validate")
	}
	again, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != id.ID {
		t.Fatal("the identity was not stable across the second run")
	}
}

package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// On-disk protection of the long-term private key.
//
// # What this achieves, precisely
//
// The threat this addresses is an attacker who obtains the FILE but not a live
// process running as the user: a stolen laptop with the disk pulled, a backup, a
// cloud-sync folder, a shared machine with a misconfigured home directory.
//
// It does NOT defend against malware already running as the user. On Windows
// that malware can call CryptUnprotectData itself; with a passphrase it can read
// the passphrase out of the environment or the process. No user-space scheme on
// a general-purpose OS changes that, and pretending otherwise would be the kind
// of claim this project is trying to avoid.
//
// # The three modes, in precedence order
//
//  1. passphrase — CMD_CHAT_IDENTITY_PASSPHRASE is set. scrypt (N=2^15, r=8,
//     p=1, 32-byte salt) stretches it into a key, and XChaCha20-Poly1305 seals
//     the Ed25519 seed. This is the strongest mode and the only one that
//     survives an attacker with full user-level access to the machine, because
//     the secret is not stored on it. It is opt-in because CMD-Chat has never
//     had a password prompt and adding a mandatory one would lock people out of
//     their own identity.
//
//  2. dpapi — Windows only, and the default there. The OS seals the seed with
//     the user's login credentials via CryptProtectData, with an application
//     entropy value so another program cannot unseal it by accident. The file
//     is useless on any other machine and to any other Windows account.
//
//  3. none — every other platform, absent a passphrase. The seed is stored as
//     it always was, in a 0600 file inside a 0700 directory. macOS Keychain and
//     the freedesktop Secret Service both need either cgo or a session D-Bus
//     that a terminal app cannot rely on, so rather than ship something that
//     silently degrades, this mode is explicit, is reported by Protection(), and
//     is documented in SECURITY.md as the weakest case.
//
// Whatever the mode, the PUBLIC key and the ID stay in cleartext: they are
// public by definition, and keeping them readable means a sealed file can still
// be identified without unsealing it.

// Protection names how the private key is protected at rest.
type Protection string

// The protection modes. See the comment above.
const (
	ProtectionNone       Protection = "none"
	ProtectionDPAPI      Protection = "dpapi"
	ProtectionPassphrase Protection = "passphrase"
)

// PassphraseEnv names the environment variable that enables passphrase
// protection.
const PassphraseEnv = "CMD_CHAT_IDENTITY_PASSPHRASE"

// scrypt parameters. N=32768 with r=8, p=1 costs about 32 MiB and a fraction of
// a second, which is the usual interactive-login recommendation and is what
// makes a stolen file expensive rather than free to attack offline.
const (
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = chacha20poly1305.KeySize
	saltLen      = 32
)

// storedIdentity is the on-disk format.
type storedIdentity struct {
	Version    int        `json:"version"`
	ID         string     `json:"id"`
	PublicKey  string     `json:"public_key"`
	Protection Protection `json:"protection"`

	// PrivateKey is set only when Protection is "none". It is the 64-byte
	// Ed25519 private key, kept in the version 1 layout so an older build can
	// still read a file this one wrote in that mode.
	PrivateKey string `json:"private_key,omitempty"`

	// Sealed is the protected 32-byte Ed25519 seed.
	Sealed string `json:"sealed,omitempty"`

	// Salt is the scrypt salt, for the passphrase mode only.
	Salt string `json:"salt,omitempty"`
}

// storeVersion is the current on-disk format version. Version 1 was the
// plaintext-only layout; it is still readable and is upgraded in place.
const storeVersion = 2

// Dir is the directory holding the identity and its neighbours.
func Dir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "cmd-chat")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// Path is the identity file.
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.json"), nil
}

// passphrase reads the configured passphrase, if any.
func passphrase() string { return strings.TrimSpace(os.Getenv(PassphraseEnv)) }

// preferredProtection picks the mode to WRITE with.
func preferredProtection() Protection {
	if passphrase() != "" {
		return ProtectionPassphrase
	}
	if dpapiAvailable() {
		return ProtectionDPAPI
	}
	return ProtectionNone
}

// StoredProtection reports how the stored identity is currently protected, so a
// user can find out rather than assume.
func StoredProtection() (Protection, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var stored storedIdentity
	if err := json.Unmarshal(data, &stored); err != nil {
		return "", err
	}
	if stored.Protection == "" {
		return ProtectionNone, nil
	}
	return stored.Protection, nil
}

// derivePassphraseKey stretches the passphrase with scrypt.
func derivePassphraseKey(salt []byte) ([]byte, error) {
	pass := passphrase()
	if pass == "" {
		return nil, fmt.Errorf("identity: %s is not set, but the stored identity needs it", PassphraseEnv)
	}
	return scrypt.Key([]byte(pass), salt, scryptN, scryptR, scryptP, scryptKeyLen)
}

// sealPassphrase encrypts the seed with XChaCha20-Poly1305 under a
// scrypt-stretched passphrase.
//
// XChaCha20's 192-bit nonce is used with a random value, which is what makes a
// random nonce safe here: the collision probability across any realistic number
// of re-seals is negligible, unlike a 96-bit nonce.
func sealPassphrase(seed []byte) (sealed, salt []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	key, err := derivePassphraseKey(salt)
	if err != nil {
		return nil, nil, err
	}
	defer wipe(key)

	box, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return box.Seal(nonce, nonce, seed, []byte("cmd-chat identity v2")), salt, nil
}

func openPassphrase(sealed, salt []byte) ([]byte, error) {
	key, err := derivePassphraseKey(salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)

	box, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("identity: sealed identity is truncated")
	}
	nonce, ciphertext := sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:]
	seed, err := box.Open(nil, nonce, ciphertext, []byte("cmd-chat identity v2"))
	if err != nil {
		return nil, errors.New("identity: wrong passphrase, or the identity file has been tampered with")
	}
	return seed, nil
}

// Save writes the identity, sealing the private key with the best available
// mechanism.
//
// The write is atomic: a temporary file in the same directory, then a rename.
// A crash halfway through used to be able to leave a truncated identity.json,
// which LoadOrCreate would discard — silently changing the user's ID and
// breaking every peer that had already pinned it.
func Save(id *Identity) error {
	if !Valid(id) {
		return errors.New("identity: refusing to store an inconsistent identity")
	}
	path, err := Path()
	if err != nil {
		return err
	}

	stored := storedIdentity{
		Version:    storeVersion,
		ID:         id.ID,
		PublicKey:  base64.StdEncoding.EncodeToString(id.PublicKey),
		Protection: preferredProtection(),
	}

	seed := id.PrivateKey.Seed()
	defer wipe(seed)

	switch stored.Protection {
	case ProtectionPassphrase:
		sealed, salt, err := sealPassphrase(seed)
		if err != nil {
			return err
		}
		stored.Sealed = base64.StdEncoding.EncodeToString(sealed)
		stored.Salt = base64.StdEncoding.EncodeToString(salt)
	case ProtectionDPAPI:
		sealed, err := dpapiProtect(seed)
		if err != nil {
			// Falling back is correct here: a machine where DPAPI is
			// unavailable must still be able to run CMD-Chat. The mode is
			// recorded honestly rather than claimed.
			stored.Protection = ProtectionNone
			stored.PrivateKey = base64.StdEncoding.EncodeToString(id.PrivateKey)
			break
		}
		stored.Sealed = base64.StdEncoding.EncodeToString(sealed)
	default:
		stored.PrivateKey = base64.StdEncoding.EncodeToString(id.PrivateKey)
	}

	// Prove the sealed blob opens again before it replaces the only copy of the
	// key.
	//
	// Sealing is the one operation here that can succeed and still produce
	// something unusable: a DPAPI call that returns a blob this machine will not
	// unseal later, or a passphrase mode misconfigured in some way. Writing that
	// over a working identity would destroy an ID that every one of the user's
	// peers has pinned, and no backup exists because keeping one would defeat
	// the point of sealing it. So the round trip is checked here, while the
	// original file is still intact.
	if err := verifySeal(stored, id); err != nil {
		return fmt.Errorf("identity: refusing to write an identity that cannot be read back: %w", err)
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}

	temp, err := os.CreateTemp(filepath.Dir(path), ".identity-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		temp.Close()
		os.Remove(tempName)
	}()
	if err := temp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrInvalid) {
		// Chmod is a no-op on Windows; a real failure elsewhere matters,
		// because the whole point of this file is that only the owner reads it.
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

// Load reads and unseals the stored identity.
func Load() (*Identity, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var stored storedIdentity
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}

	public, err := base64.StdEncoding.DecodeString(stored.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("identity: stored public key is unusable")
	}

	var private ed25519.PrivateKey
	switch stored.Protection {
	case "", ProtectionNone:
		// Version 1 files and version 2 unprotected files look the same here.
		raw, err := base64.StdEncoding.DecodeString(stored.PrivateKey)
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("identity: stored private key is unusable")
		}
		private = ed25519.PrivateKey(raw)

	case ProtectionPassphrase:
		sealed, err := base64.StdEncoding.DecodeString(stored.Sealed)
		if err != nil {
			return nil, errors.New("identity: stored key is unusable")
		}
		salt, err := base64.StdEncoding.DecodeString(stored.Salt)
		if err != nil || len(salt) != saltLen {
			return nil, errors.New("identity: stored key salt is unusable")
		}
		seed, err := openPassphrase(sealed, salt)
		if err != nil {
			return nil, err
		}
		defer wipe(seed)
		private = ed25519.NewKeyFromSeed(seed)

	case ProtectionDPAPI:
		sealed, err := base64.StdEncoding.DecodeString(stored.Sealed)
		if err != nil {
			return nil, errors.New("identity: stored key is unusable")
		}
		seed, err := dpapiUnprotect(sealed)
		if err != nil {
			return nil, err
		}
		defer wipe(seed)
		if len(seed) != ed25519.SeedSize {
			return nil, errors.New("identity: unsealed key has the wrong size")
		}
		private = ed25519.NewKeyFromSeed(seed)

	default:
		// An unknown protection mode fails closed. Guessing would risk
		// discarding a perfectly good identity and silently minting a new ID.
		return nil, fmt.Errorf("identity: unsupported key protection %q; this file was written by a newer CMD-Chat", stored.Protection)
	}

	id := &Identity{PrivateKey: private, PublicKey: ed25519.PublicKey(public), ID: stored.ID}
	if id.ID == "" {
		id.ID = DeriveID(id.PublicKey)
	}
	if !Valid(id) {
		return nil, errors.New("identity: stored identity is inconsistent")
	}

	// Upgrade an older or weaker-than-available file in place. A failure here is
	// not fatal: the identity loaded fine, and refusing to start over a
	// re-seal would be worse than running with the protection already in place.
	if stored.Version < storeVersion || stored.Protection != preferredProtection() {
		_ = Save(id)
	}
	return id, nil
}

// wipe zeroes a buffer. See e2ee.Wipe for the honest limitations of doing this
// in Go; the same caveats apply.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// verifySeal reopens a freshly sealed record and checks it yields the same key.
func verifySeal(stored storedIdentity, want *Identity) error {
	switch stored.Protection {
	case "", ProtectionNone:
		raw, err := base64.StdEncoding.DecodeString(stored.PrivateKey)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, want.PrivateKey) {
			return errors.New("the encoded private key does not match")
		}
		return nil

	case ProtectionPassphrase:
		sealed, err := base64.StdEncoding.DecodeString(stored.Sealed)
		if err != nil {
			return err
		}
		salt, err := base64.StdEncoding.DecodeString(stored.Salt)
		if err != nil {
			return err
		}
		seed, err := openPassphrase(sealed, salt)
		if err != nil {
			return err
		}
		defer wipe(seed)
		if !bytes.Equal(seed, want.PrivateKey.Seed()) {
			return errors.New("the sealed key did not round-trip")
		}
		return nil

	case ProtectionDPAPI:
		sealed, err := base64.StdEncoding.DecodeString(stored.Sealed)
		if err != nil {
			return err
		}
		seed, err := dpapiUnprotect(sealed)
		if err != nil {
			return err
		}
		defer wipe(seed)
		if !bytes.Equal(seed, want.PrivateKey.Seed()) {
			return errors.New("the sealed key did not round-trip")
		}
		return nil

	default:
		return fmt.Errorf("unknown protection mode %q", stored.Protection)
	}
}

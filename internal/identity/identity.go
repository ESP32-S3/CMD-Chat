// Package identity holds the long-term Ed25519 keypair that gives a CMD-Chat
// user a stable name.
//
// The key here does exactly one thing: it SIGNS. It never encrypts a message and
// it never derives a message key. That separation is what makes forward secrecy
// possible — see internal/e2ee — because recovering this key later reveals
// nothing about conversations that were captured earlier.
//
// At rest the private key is protected by the strongest mechanism the platform
// offers without inventing a password prompt where there was not one before; see
// store.go for exactly what that means on each platform, and what it does not
// mean.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
)

// Identity is one user's long-term keypair and the ID it derives.
type Identity struct {
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	ID         string             `json:"id"`
}

// DeriveID computes the stable CMD-Chat ID for a public key.
//
//	cc- || base32(SHA-256(publicKey)[0:10])
//
// This is the single definition. internal/auth, internal/e2ee and the two
// Cloudflare Workers all agree with it, and a peer's claimed ID is always
// recomputed from its key rather than believed.
//
// Note on strength: ten bytes is 80 bits, which gives roughly 80-bit resistance
// to producing a key that matches a SPECIFIC target ID, and roughly 40-bit
// resistance to finding any colliding PAIR. The second number is the weak one.
// It is a property of the existing, published ID format rather than of this
// function, and changing it would invalidate every ID people have already
// shared; SECURITY.md records it as a known limitation.
func DeriveID(public ed25519.PublicKey) string {
	h := sha256.Sum256(public)
	return "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:10])
}

// Valid reports whether an identity is internally consistent: the private key
// really derives the public key, and the ID really derives from the public key.
func Valid(i *Identity) bool {
	return i != nil &&
		len(i.PrivateKey) == ed25519.PrivateKeySize &&
		len(i.PublicKey) == ed25519.PublicKeySize &&
		i.PrivateKey.Public().(ed25519.PublicKey).Equal(i.PublicKey) &&
		i.ID == DeriveID(i.PublicKey)
}

// Generate creates a fresh identity from the system CSPRNG.
func Generate() (*Identity, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{PrivateKey: private, PublicKey: public, ID: DeriveID(public)}, nil
}

// LoadOrCreate returns the identity on this computer, creating one only on
// first run.
//
// # Why this refuses to replace a broken identity
//
// A CMD-Chat ID is not a login that can be reissued. It is the name every peer
// has pinned, and it is the thing that makes a reconnection safe: a peer that
// sees a DIFFERENT key for a known ID refuses the connection outright. Silently
// minting a new identity because the stored one would not open would therefore
// do the worst possible thing — change the user's ID, and make every friend they
// have see the exact signature of an impersonation attempt.
//
// So: an identity file that EXISTS but cannot be read is an error, and the error
// is returned. Only a genuinely absent file produces a new identity.
//
// The cases this matters for are real ones. A passphrase typo. Restoring a
// backup onto a different Windows account, where DPAPI cannot unseal. A file
// written by a newer build using a protection mode this one does not know. In
// every one of those the right answer is to say so and stop, so the user can fix
// it, rather than to quietly hand them a new name.
func LoadOrCreate() (*Identity, error) {
	id, err := Load()
	switch {
	case err == nil && Valid(id):
		return id, nil
	case err == nil:
		// The file parsed but is internally inconsistent: the private key does
		// not derive the public key, or the ID does not derive from the key.
		// Such an identity cannot prove anything to anyone, so it is not worth
		// preserving — but it is still worth being loud about.
		return nil, fmt.Errorf("identity: the stored identity at %s is inconsistent and cannot be used; move it aside to start fresh", pathForMessage())
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("identity: could not open the stored identity at %s: %w", pathForMessage(), err)
	}

	fresh, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := Save(fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

// pathForMessage is the identity path for use in an error, or a placeholder when
// even that cannot be determined.
func pathForMessage() string {
	path, err := Path()
	if err != nil {
		return "the CMD-Chat configuration directory"
	}
	return path
}

// Sign produces an Ed25519 signature over data.
//
// Callers must always sign a domain-separated message; see internal/e2ee and
// internal/phonebook for the labels in use. Signing a bare value would let a
// signature made for one purpose be replayed as another.
func (i *Identity) Sign(data []byte) []byte { return ed25519.Sign(i.PrivateKey, data) }

// Verify checks an Ed25519 signature.
func Verify(public ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(public, data, signature)
}

// Short abbreviates an ID for display.
func Short(id string) string {
	if len(id) <= 14 {
		return id
	}
	return fmt.Sprintf("%s…", id[:14])
}

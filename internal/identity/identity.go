package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is a permanent cryptographic identity. The private key never leaves
// the device. The public key becomes the user's stable identifier.
type Identity struct {
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	ID         string             `json:"id"`
}

func identityPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "cmd-chat")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.json"), nil
}

func LoadOrCreate() (*Identity, error) {
	path, err := identityPath()
	if err != nil {
		return nil, err
	}

	if data, err := os.ReadFile(path); err == nil {
		var id Identity
		if json.Unmarshal(data, &id) == nil && len(id.PrivateKey) == ed25519.PrivateKeySize {
			return &id, nil
		}
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(public)
	id := &Identity{
		PrivateKey: private,
		PublicKey: public,
		ID: "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:10]),
	}

	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}

	return id, nil
}

func (i *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(i.PrivateKey, data)
}

func Verify(public ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(public, data, signature)
}

func Short(id string) string {
	if len(id) <= 14 {
		return id
	}
	return fmt.Sprintf("%s…", id[:14])
}

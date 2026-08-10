package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// Challenge is a fresh nonce used to prove possession of a private key.
type Challenge struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
}

// Response proves ownership of the identity that claims ID.
type Response struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

func NewChallenge() (*Challenge, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil { return nil, err }
	return &Challenge{Type: "auth_challenge", Nonce: base64.StdEncoding.EncodeToString(nonce)}, nil
}

func Respond(id *identity.Identity, challenge *Challenge) (*Response, error) {
	if challenge == nil || challenge.Nonce == "" { return nil, errors.New("missing authentication challenge") }
	nonce, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil { return nil, err }
	payload := append([]byte("CMD-CHAT/1\x00"+id.ID+"\x00"), nonce...)
	return &Response{
		Type: "auth_response", ID: id.ID,
		PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		Nonce: challenge.Nonce,
		Signature: base64.StdEncoding.EncodeToString(id.Sign(payload)),
	}, nil
}

func Verify(challenge *Challenge, response *Response) error {
	if challenge == nil || response == nil || response.Nonce != challenge.Nonce { return errors.New("authentication nonce mismatch") }
	pub, err := base64.StdEncoding.DecodeString(response.PublicKey); if err != nil { return err }
	if len(pub) != ed25519.PublicKeySize { return errors.New("invalid public key") }
	h := sha256.Sum256(pub)
	expected := "cc-" + base32NoPadding(h[:10])
	if response.ID != expected { return errors.New("identity does not match public key") }
	nonce, err := base64.StdEncoding.DecodeString(response.Nonce); if err != nil { return err }
	sig, err := base64.StdEncoding.DecodeString(response.Signature); if err != nil { return err }
	payload := append([]byte("CMD-CHAT/1\x00"+response.ID+"\x00"), nonce...)
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) { return errors.New("invalid identity signature") }
	return nil
}

func base32NoPadding(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	out := make([]byte, 0, (len(b)*8+4)/5)
	var acc uint32; bits := 0
	for _, v := range b { acc = (acc << 8) | uint32(v); bits += 8; for bits >= 5 { bits -= 5; out = append(out, alphabet[(acc>>bits)&31]) } }
	if bits > 0 { out = append(out, alphabet[(acc<<(5-bits))&31]) }
	return string(out)
}

func Fingerprint(publicKey string) string {
	b, err := base64.StdEncoding.DecodeString(publicKey); if err != nil { return "" }
	h := sha256.Sum256(b); return fmt.Sprintf("%x", h[:])
}

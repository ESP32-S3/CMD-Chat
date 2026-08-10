package auth

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "errors"

    "github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// Handshake proves ownership of a persistent CMD-Chat identity.
type Handshake struct {
    ID string `json:"id"`
    PublicKey string `json:"public_key"`
    Nonce string `json:"nonce"`
    Signature string `json:"signature"`
}

func Create(id *identity.Identity) (*Handshake, error) {
    nonce := make([]byte, 32)
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    payload := append([]byte(id.ID), nonce...)
    sig := id.Sign(payload)
    return &Handshake{
        ID: id.ID,
        PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
        Nonce: base64.StdEncoding.EncodeToString(nonce),
        Signature: base64.StdEncoding.EncodeToString(sig),
    }, nil
}

func Verify(h Handshake) error {
    pub, err := base64.StdEncoding.DecodeString(h.PublicKey)
    if err != nil {
        return err
    }
    nonce, err := base64.StdEncoding.DecodeString(h.Nonce)
    if err != nil {
        return err
    }
    sig, err := base64.StdEncoding.DecodeString(h.Signature)
    if err != nil {
        return err
    }
    if !ed25519.Verify(ed25519.PublicKey(pub), append([]byte(h.ID), nonce...), sig) {
        return errors.New("invalid identity signature")
    }
    return nil
}

func Encode(h Handshake) ([]byte, error) { return json.Marshal(h) }

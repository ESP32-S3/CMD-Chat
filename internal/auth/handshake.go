package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Fingerprint renders a base64 Ed25519 public key as a hex SHA-256 digest, for
// display when a user needs to compare a key out of band.
//
// The mutual challenge/response that used to live in this file has been removed.
// It signed only "CMD-CHAT/1" || ID || nonce, which said nothing about WHICH TLS
// session it ran inside, so an attacker terminating TLS on both sides could
// forward it verbatim and sit in the middle of an apparently authenticated
// conversation. Peer authentication is now internal/e2ee's CMDC1 handshake,
// which is bound to the TLS session by an RFC 5705 exporter and cannot be
// forwarded. See docs/SECURITY-BASELINE.md, weakness W1.
func Fingerprint(publicKey string) string {
	b, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

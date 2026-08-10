package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"testing"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

func testIdentity(t *testing.T) *identity.Identity {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	h := sha256.Sum256(pub)
	return &identity.Identity{PrivateKey: priv, PublicKey: pub, ID: "cc-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:10])}
}

func TestMutualChallengeResponse(t *testing.T) {
	alice, bob := testIdentity(t), testIdentity(t)
	ca, _ := NewChallenge()
	ra, err := Respond(alice, ca); if err != nil { t.Fatal(err) }
	if err := Verify(ca, ra); err != nil { t.Fatal(err) }
	cb, _ := NewChallenge()
	rb, err := Respond(bob, cb); if err != nil { t.Fatal(err) }
	if err := Verify(cb, rb); err != nil { t.Fatal(err) }
	if Verify(ca, rb) == nil { t.Fatal("accepted response to wrong challenge") }
}

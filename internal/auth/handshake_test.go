package auth

import (
	"testing"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

func TestMutualChallengeResponse(t *testing.T) {
	alice, err := identity.LoadOrCreateForTest()
	if err != nil { t.Fatal(err) }
	bob, err := identity.LoadOrCreateForTest()
	if err != nil { t.Fatal(err) }
	ca, _ := NewChallenge()
	ra, err := Respond(alice, ca); if err != nil { t.Fatal(err) }
	if err := Verify(ca, ra); err != nil { t.Fatal(err) }
	cb, _ := NewChallenge()
	rb, err := Respond(bob, cb); if err != nil { t.Fatal(err) }
	if err := Verify(cb, rb); err != nil { t.Fatal(err) }
	if Verify(ca, rb) == nil { t.Fatal("accepted response to wrong challenge") }
}

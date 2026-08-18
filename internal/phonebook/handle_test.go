package phonebook

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

func testID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

// A guest must be able to derive the handle from nothing but the ID a human
// typed, or the directory could not be used at all.
func TestHandleIsDerivableFromTheIDAlone(t *testing.T) {
	id := testID(t)

	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(handle) != HandleLength {
		t.Fatalf("handle is %d characters, want %d", len(handle), HandleLength)
	}
	for _, r := range handle {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", r) {
			t.Fatalf("handle contains %q, which is outside base32", r)
		}
	}

	// Deterministic: the guest and the host must land on the same row.
	again, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}
	if handle != again {
		t.Fatal("Handle is not deterministic; a guest could never find a host")
	}
}

// The handle must not be the ID, or a blinded directory would be pointless.
func TestHandleRevealsNoID(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}

	if handle == id.ID {
		t.Fatal("the handle is the ID")
	}
	if strings.Contains(handle, strings.TrimPrefix(id.ID, "cc-")) {
		t.Fatal("the handle contains the ID's body")
	}
	// A one-character change anywhere in the ID must change the handle.
	body := []byte(strings.TrimPrefix(id.ID, "cc-"))
	for i := range body {
		altered := append([]byte(nil), body...)
		if altered[i] == 'A' {
			altered[i] = 'B'
		} else {
			altered[i] = 'A'
		}
		other, err := Handle("cc-" + string(altered))
		if err != nil {
			continue // not a valid ID shape; skip
		}
		if other == handle {
			t.Fatalf("changing character %d of the ID did not change the handle", i)
		}
	}
}

func TestHandleRejectsAMalformedID(t *testing.T) {
	for _, bad := range []string{"", "not-an-id", "cc-", "cc-TOOSHORT", strings.Repeat("A", 40)} {
		if _, err := Handle(bad); err == nil {
			t.Fatalf("Handle(%q) succeeded", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// The write key
// ---------------------------------------------------------------------------

// The directory sees the write key on every request, so it must reveal nothing
// about the identity behind it.
func TestWriteKeyIsUnlinkableToTheIdentity(t *testing.T) {
	id := testID(t)

	writeKey, err := WriteKey(id)
	if err != nil {
		t.Fatalf("WriteKey: %v", err)
	}
	writePub := writeKey.Public().(ed25519.PublicKey)

	if bytes.Equal(writePub, id.PublicKey) {
		t.Fatal("the write key IS the identity key; the directory would learn the identity from every write")
	}
	if bytes.Equal(writeKey, id.PrivateKey) {
		t.Fatal("the write private key is the identity private key")
	}
	// The ID must not be recoverable from the write key by the one obvious route.
	if identity.DeriveID(writePub) == id.ID {
		t.Fatal("the write public key derives the CMD-Chat ID")
	}

	// Deterministic, so it survives a restart with no extra state.
	again, err := WriteKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writeKey, again) {
		t.Fatal("WriteKey is not deterministic; a restart would lose ownership of the handle")
	}

	// Different identities get different write keys.
	other, err := WriteKey(testID(t))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(writeKey, other) {
		t.Fatal("two identities produced the same write key")
	}
}

// The write key must actually work as a signing key.
func TestWriteKeySigns(t *testing.T) {
	id := testID(t)
	writeKey, err := WriteKey(id)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("cmd-chat-phonebook/v2\nPOST\n/v2/publish\n1\nabc")
	signature := ed25519.Sign(writeKey, message)
	if !ed25519.Verify(writeKey.Public().(ed25519.PublicKey), message, signature) {
		t.Fatal("a signature by the write key did not verify under its own public key")
	}
	// And must not verify under the identity key.
	if ed25519.Verify(id.PublicKey, message, signature) {
		t.Fatal("a write-key signature verified under the identity key")
	}
}

func TestWriteKeyRefusesAnEmptyIdentity(t *testing.T) {
	if _, err := WriteKey(nil); err == nil {
		t.Fatal("WriteKey(nil) succeeded")
	}
	if _, err := WriteKey(&identity.Identity{}); err == nil {
		t.Fatal("WriteKey with no private key succeeded")
	}
}

// ---------------------------------------------------------------------------
// The sealed entry
// ---------------------------------------------------------------------------

func sampleEntry(id string) entry {
	return entry{
		ID:              id,
		Fingerprint:     strings.Repeat("a", 64),
		ProtocolVersion: 2,
		ClientVersion:   "v2.4.0",
		Candidates: []Candidate{
			{Kind: KindHost, Transport: "tcp", Address: "192.168.1.42", Port: intPtr(38556), Priority: 100},
			{Kind: KindServerReflexive, Transport: "udp", Address: "203.0.113.9", Port: intPtr(51820), Priority: 200},
		},
	}
}

// The round trip has to work, or nobody can connect.
func TestSealedEntryRoundTrips(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := seal(id.ID, handle, sampleEntry(id.ID))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	opened, err := open(id.ID, handle, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.ID != id.ID {
		t.Fatalf("opened entry names %q", opened.ID)
	}
	if len(opened.Candidates) != 2 {
		t.Fatalf("got %d candidates", len(opened.Candidates))
	}
	if opened.Candidates[0].Address != "192.168.1.42" {
		t.Fatalf("candidate address = %q", opened.Candidates[0].Address)
	}
	if opened.ProtocolVersion != 2 {
		t.Fatalf("protocol version = %d", opened.ProtocolVersion)
	}
}

// This is the property the whole design exists for: what goes on the wire must
// contain no ID and no address.
func TestSealedEntryLeaksNothing(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := seal(id.ID, handle, sampleEntry(id.ID))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("the sealed entry is not base64: %v", err)
	}

	for _, secret := range []string{
		id.ID,
		strings.TrimPrefix(id.ID, "cc-"),
		"192.168.1.42",
		"203.0.113.9",
		"38556",
		strings.Repeat("a", 64),
		KindHost,
	} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("%q appears in the sealed entry in the clear", secret)
		}
		if strings.Contains(sealed, secret) {
			t.Fatalf("%q appears in the encoded sealed entry", secret)
		}
	}
}

// Only the right ID opens an entry. Anybody else — including the directory —
// gets nothing.
func TestSealedEntryOnlyOpensWithTheRightID(t *testing.T) {
	owner, stranger := testID(t), testID(t)
	handle, err := Handle(owner.ID)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := seal(owner.ID, handle, sampleEntry(owner.ID))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := open(stranger.ID, handle, sealed); err == nil {
		t.Fatal("a different ID opened the entry")
	}
}

// A blob cannot be lifted out of one row and served in another, because the
// handle is the associated data.
func TestSealedEntryIsBoundToItsHandle(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(id.ID, handle, sampleEntry(id.ID))
	if err != nil {
		t.Fatal(err)
	}

	other, err := Handle(testID(t).ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(id.ID, other, sealed); err == nil {
		t.Fatal("a sealed entry opened under a different handle")
	}
}

// Any tampering must be caught, so a hostile directory cannot rewrite an entry.
func TestTamperedSealedEntryIsRejected(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(id.ID, handle, sampleEntry(id.ID))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}

	for _, at := range []int{0, 12, len(raw) / 2, len(raw) - 1} {
		forged := append([]byte(nil), raw...)
		forged[at] ^= 0x01
		if _, err := open(id.ID, handle, base64.StdEncoding.EncodeToString(forged)); err == nil {
			t.Fatalf("a sealed entry tampered at byte %d was accepted", at)
		}
	}
}

// An entry naming a different peer must be refused even if it decrypts, which
// keeps the ErrDirectoryMismatch contract exact.
func TestSealedEntryNamingAnotherPeerIsRejected(t *testing.T) {
	owner, other := testID(t), testID(t)
	handle, err := Handle(owner.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Sealed under the owner's key, but claiming to be somebody else.
	sealed, err := seal(owner.ID, handle, sampleEntry(other.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(owner.ID, handle, sealed); err == nil {
		t.Fatal("an entry naming a different peer was accepted")
	}
}

func TestMalformedSealedEntriesAreRejected(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string]string{
		"empty":        "",
		"not base64":   "!!!!not base64!!!!",
		"too short":    base64.StdEncoding.EncodeToString([]byte("short")),
		"oversized":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, MaxSealedBytes+1)),
		"only a nonce": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 24)),
	} {
		if _, err := open(id.ID, handle, bad); err == nil {
			t.Fatalf("a %s sealed entry was accepted", name)
		}
	}
}

// Two seals of the same entry must differ, so the directory cannot tell that a
// republish changed nothing.
func TestSealingIsRandomised(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for i := range 8 {
		sealed, err := seal(id.ID, handle, sampleEntry(id.ID))
		if err != nil {
			t.Fatal(err)
		}
		if seen[sealed] {
			t.Fatalf("seal %d reproduced an earlier ciphertext", i)
		}
		seen[sealed] = true
	}
}

// A full candidate set must fit inside the cap the Worker will accept.
func TestAFullEntryFitsTheSizeCap(t *testing.T) {
	id := testID(t)
	handle, err := Handle(id.ID)
	if err != nil {
		t.Fatal(err)
	}

	full := entry{
		ID:              id.ID,
		Fingerprint:     strings.Repeat("f", 64),
		ProtocolVersion: 2,
		ClientVersion:   "v2.4.0-with-a-long-suffix",
	}
	for i := range 8 {
		full.Candidates = append(full.Candidates, Candidate{
			Kind:      KindHost,
			Transport: "tcp",
			Address:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			Port:      intPtr(38556 + i),
			Priority:  100,
		})
	}

	sealed, err := seal(id.ID, handle, full)
	if err != nil {
		t.Fatalf("a full candidate set would not seal: %v", err)
	}
	// The Worker's limit is on the base64 length.
	const workerLimit = 2800
	if len(sealed) > workerLimit {
		t.Fatalf("a full entry encodes to %d characters, above the Worker's %d limit", len(sealed), workerLimit)
	}
	if _, err := open(id.ID, handle, sealed); err != nil {
		t.Fatalf("a full entry did not round-trip: %v", err)
	}
}

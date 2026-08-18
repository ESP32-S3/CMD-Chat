package phonebook

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// Blinded phonebook entries: how CMD-Chat stops the directory from holding a
// table of "this person is at this address".
//
// # The problem this solves
//
// The v1 directory stored a row keyed by CMD-Chat ID with the peer's IP
// addresses in a child table. A single JOIN produced exactly the thing a
// rendezvous service should never accumulate: a live map of identity to
// location, for every user, readable by whoever holds the database — including
// anyone who compels or breaches Cloudflare. Worse, the Worker itself appended
// the public IP it observed and persisted that too, so the map was populated
// even for peers that published nothing.
//
// # What replaces it
//
// The directory now stores, per peer:
//
//	handle     a 128-bit blinded row key
//	write_key  an Ed25519 public key that is unlinkable to the identity
//	sealed     an AEAD ciphertext holding everything else
//
// There is no CMD-Chat ID in the database, no identity public key, and no IP
// address in any readable form. A dump of the table is a list of opaque handles
// and opaque blobs.
//
// # The derivations
//
// The insight is that a guest ALREADY knows the one thing the directory must
// not: the peer's ID, because a human typed it. So the ID can key both the row
// lookup and the encryption, and the directory can be handed neither.
//
//	handle    = base32( HKDF-SHA256(ikm = ID,            info = "…handle",    16) )
//	entryKey  = HKDF-SHA256(ikm = ID,            info = "…entry key", 32)
//	writeSeed = HKDF-SHA256(ikm = identity seed, info = "…write key", 32)
//
// handle and entryKey come from the ID, which is public among the people you
// have given it to — that is the point, they need to find and read your entry.
// writeSeed comes from the identity's PRIVATE seed, so the write key it produces
// is pseudorandom to anyone who has not got that seed, and cannot be linked back
// to the identity public key. The directory sees it and learns nothing.
//
// # What this does and does not hide
//
// It defeats BULK extraction. Whoever holds the database cannot enumerate users,
// cannot map identities to addresses, and cannot learn where anyone is.
//
// It does NOT defeat TARGETED CONFIRMATION. The derivation is deterministic, so
// somebody who already has a specific ID — because it was posted publicly, or
// they were given it — can compute that ID's handle and entry key and check
// whether it is registered and read its addresses. Making that impossible would
// need private information retrieval, which is orders of magnitude more
// expensive than this whole service.
//
// It also does not change what the Worker sees WHILE SERVING A REQUEST: the
// source IP of every call is visible to Cloudflare's edge by construction. What
// changed is that none of it is written down. SECURITY.md states both limits.
//
// # The trade that was made deliberately
//
// v1 authorised a write by checking that the supplied public key hashed to the
// ID being modified, so only the identity key could touch a row. A directory
// that does not know the ID cannot make that check. Instead the FIRST writer of
// a handle binds its write key to it, and only that key may update it after
// that.
//
// The consequence, stated plainly: somebody who already knows your ID could
// claim your handle before you do and cause your friends' connection attempts to
// fail or go to an address they chose. They cannot impersonate you — CMDC2
// authenticates the peer's real identity key end to end, and a wrong peer fails
// the handshake — and they cannot read anything. LAN discovery and the relay are
// unaffected. That is a denial-of-service problem available to people you have
// already given your ID to, traded for removing the identity-to-address map
// entirely.

// Domain-separation labels. One label, one purpose; see internal/e2ee/labels.go
// for the same rule applied to the message protocol.
const (
	labelHandle   = "cmd-chat phonebook v2 handle"
	labelEntryKey = "cmd-chat phonebook v2 entry key"
	labelWriteKey = "cmd-chat phonebook v2 write key"

	// labelSealedAD is the associated data of a sealed entry, mixed with the
	// handle so a blob cannot be lifted from one row into another.
	labelSealedAD = "cmd-chat phonebook v2 entry"
)

// HandleBytes is the length of the blinded row key before encoding. 16 bytes is
// 128 bits, which is far beyond any realistic attempt to enumerate the space,
// and encodes to exactly 26 base32 characters.
const HandleBytes = 16

// HandleLength is the encoded handle length, fixed so the Worker can CHECK it.
const HandleLength = 26

// MaxSealedBytes bounds a sealed entry, in raw bytes before base64.
//
// Eight candidates, a fingerprint and two version numbers come to roughly 700
// bytes, so this is generous. The cap exists so the directory cannot be used as
// free storage, and it is set below the Worker's own limit — 2048 raw encodes to
// 2732 base64 characters against its 2800 — so an entry this client is willing to
// build is always one the Worker is willing to accept.
const MaxSealedBytes = 2048

var handleEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// derive runs HKDF-SHA256 with a purpose label.
func derive(ikm []byte, label string, out int) ([]byte, error) {
	buf := make([]byte, out)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte(label)), buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Handle is the blinded directory key for a CMD-Chat ID.
//
// It is what the Worker stores and what a lookup asks for. Deriving it needs
// only the ID, so a guest that has typed a friend's ID can find them, and the
// directory — which never receives the ID — cannot go the other way.
func Handle(id string) (string, error) {
	if !ValidID(id) {
		return "", fmt.Errorf("phonebook: %q is not a valid CMD-Chat ID", id)
	}
	raw, err := derive([]byte(id), labelHandle, HandleBytes)
	if err != nil {
		return "", err
	}
	return handleEncoding.EncodeToString(raw), nil
}

// entryKey is the AEAD key for a peer's sealed entry, derived from its ID.
func entryKey(id string) ([]byte, error) {
	return derive([]byte(id), labelEntryKey, chacha20poly1305.KeySize)
}

// WriteKey derives the Ed25519 keypair this identity uses to authorise directory
// writes.
//
// It is deliberately NOT the identity key. The directory sees this public key on
// every write, and a value derived one-way from the identity's private seed
// tells it nothing about who the writer is. Using the identity key here would
// put the identity straight back into the database.
//
// It is deterministic, so it survives a restart without any extra state to
// store, lose, or leak.
func WriteKey(id *identity.Identity) (ed25519.PrivateKey, error) {
	if id == nil || len(id.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("phonebook: no identity to derive a write key from")
	}
	seed := id.PrivateKey.Seed()
	defer wipe(seed)

	writeSeed, err := derive(seed, labelWriteKey, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer wipe(writeSeed)
	return ed25519.NewKeyFromSeed(writeSeed), nil
}

// entry is the plaintext inside a sealed directory record.
//
// The ID is included so a guest can confirm the entry it decrypted really is the
// peer it asked for. Decryption succeeding already implies the writer knew the
// ID, but checking explicitly keeps the ErrDirectoryMismatch contract exact and
// costs one string comparison.
type entry struct {
	ID              string      `json:"id"`
	Fingerprint     string      `json:"session_fingerprint,omitempty"`
	ProtocolVersion int         `json:"protocol_version"`
	ClientVersion   string      `json:"client_version,omitempty"`
	Candidates      []Candidate `json:"candidates"`
}

// seal encrypts an entry for storage.
//
// XChaCha20-Poly1305 with a random 192-bit nonce: at that width a random nonce
// is safe without any counter to keep, which matters because the same entry is
// re-sealed on every republish and there is nowhere durable to keep a counter.
func seal(id, handle string, e entry) (string, error) {
	plaintext, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	defer wipe(plaintext)

	key, err := entryKey(id)
	if err != nil {
		return "", err
	}
	defer wipe(key)

	box, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	sealed := box.Seal(nonce, nonce, plaintext, associatedData(handle))
	if len(sealed) > MaxSealedBytes {
		return "", fmt.Errorf("phonebook: sealed entry is %d bytes, above the %d-byte limit", len(sealed), MaxSealedBytes)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// open decrypts a sealed entry and checks it belongs to the ID that was asked
// for.
//
// Every failure here becomes ErrDirectoryMismatch at the call site rather than a
// distinct error. From the caller's point of view a blob it cannot open and a
// blob for the wrong peer are the same thing: the directory did not return the
// entry that was requested, and connecting would be wrong.
func open(id, handle, encoded string) (*entry, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("phonebook: sealed entry is not valid base64")
	}
	if len(raw) < chacha20poly1305.NonceSizeX+16 {
		return nil, errors.New("phonebook: sealed entry is truncated")
	}
	if len(raw) > MaxSealedBytes {
		return nil, errors.New("phonebook: sealed entry is oversized")
	}

	key, err := entryKey(id)
	if err != nil {
		return nil, err
	}
	defer wipe(key)

	box, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := raw[:chacha20poly1305.NonceSizeX], raw[chacha20poly1305.NonceSizeX:]
	plaintext, err := box.Open(nil, nonce, ciphertext, associatedData(handle))
	if err != nil {
		return nil, errors.New("phonebook: the stored entry could not be opened with this ID")
	}
	defer wipe(plaintext)

	var e entry
	if err := json.Unmarshal(plaintext, &e); err != nil {
		return nil, errors.New("phonebook: the stored entry is not a directory record")
	}
	if e.ID != id {
		return nil, fmt.Errorf("phonebook: the stored entry names %s, not %s", e.ID, id)
	}
	return &e, nil
}

// associatedData binds a sealed blob to its row.
func associatedData(handle string) []byte {
	return []byte(labelSealedAD + "\x00" + handle)
}

// wipe zeroes a buffer. Same honest limitations as e2ee.Wipe; this is not
// imported from there to keep the directory client free of a dependency on the
// message protocol.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SealAnnouncement produces the blinded handle and the sealed entry a host
// publishes for an announcement.
//
// Register uses this, and it is exported because anything that needs to speak
// the directory protocol — a test double, a future re-publisher, a diagnostic —
// needs to produce exactly the same two values, and reimplementing the
// derivations somewhere else is how they drift apart.
func SealAnnouncement(id string, a Announcement, clientVersion string) (handle, sealed string, err error) {
	if !ValidID(id) {
		return "", "", fmt.Errorf("phonebook: %q is not a valid CMD-Chat ID", id)
	}
	handle, err = Handle(id)
	if err != nil {
		return "", "", err
	}
	version := a.ProtocolVersion
	if version <= 0 {
		version = 1
	}
	sealed, err = seal(id, handle, entry{
		ID:              id,
		Fingerprint:     strings.ToLower(a.Fingerprint),
		ProtocolVersion: version,
		ClientVersion:   clientVersion,
		Candidates:      a.Candidates,
	})
	if err != nil {
		return "", "", err
	}
	return handle, sealed, nil
}

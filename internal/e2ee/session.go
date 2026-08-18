package e2ee

import (
	"crypto/ecdh"
	"errors"
	"io"
	"sync"
	"time"
)

// role records which side of the handshake this session was.
type role uint8

const (
	roleInitiator role = iota
	roleResponder
)

// Rekey policy.
//
// The DH ratchet only turns when the PEER sends. In a one-sided conversation —
// one person typing, the other reading — the sender's chain would ratchet
// symmetrically forever without ever mixing fresh DH material, so post-compromise
// security would never actually kick in. These bounds make the chat layer prompt
// the peer for a reply, which necessarily carries a new ratchet public key.
const (
	// RekeyAfterMessages is how many messages this side may send without a DH
	// ratchet step before it asks the peer to answer.
	RekeyAfterMessages = 64

	// RekeyAfterInterval is how long this side may go without a DH ratchet step
	// before it asks the peer to answer.
	RekeyAfterInterval = 5 * time.Minute
)

// ErrSessionClosed is returned once a session has been closed.
var ErrSessionClosed = errors.New("e2ee: session is closed")

// Session is an established CMDC2 channel between two authenticated identities.
//
// It is safe for concurrent use: one goroutine may send while another receives,
// which is exactly what the chat layer does.
type Session struct {
	mu      sync.Mutex
	ratchet *ratchet
	closed  bool

	// associated is the 32-byte session tag mixed into every record's
	// associated data. It binds each ciphertext to this handshake transcript, so
	// a record captured from an earlier session between the same two people
	// fails authentication instead of being accepted after a reconnect.
	associated []byte

	peer PeerInfo
	role role

	// sentSinceStep and lastStep drive NeedsRekey.
	sentSinceStep int
	lastStep      time.Time
	steps         uint64
}

// newSession completes the handshake by deriving the session keys and starting
// the ratchet.
//
// Exactly one of peerEphemeral (initiator) and ownEphemeral (responder) is set.
func newSession(prk, th4 []byte, peer PeerInfo, r role, peerEphemeral *ecdh.PublicKey, ownEphemeral *ecdh.PrivateKey, random io.Reader) (*Session, error) {
	defer Wipe(prk)

	rootKey, err := hkdfExpand(prk, append([]byte(labelRootKey), th4...), keySize)
	if err != nil {
		return nil, err
	}
	associated, err := hkdfExpand(prk, append([]byte(labelAssociatedTag), th4...), keySize)
	if err != nil {
		Wipe(rootKey)
		return nil, err
	}

	s := &Session{associated: associated, peer: peer, role: r, lastStep: time.Now()}
	switch r {
	case roleInitiator:
		if peerEphemeral == nil {
			return nil, errors.New("e2ee: initiator session without a peer ratchet key")
		}
		// newRatchetInitiator consumes and wipes rootKey.
		s.ratchet, err = newRatchetInitiator(rootKey, peerEphemeral, random)
		if err != nil {
			Wipe(associated)
			return nil, err
		}
	case roleResponder:
		if ownEphemeral == nil {
			return nil, errors.New("e2ee: responder session without an ephemeral key")
		}
		s.ratchet = newRatchetResponder(rootKey, ownEphemeral, random)
	}
	return s, nil
}

// Peer describes the authenticated far side.
func (s *Session) Peer() PeerInfo { return s.peer }

// Close wipes every key the session holds.
//
// See Wipe for what "wipes" honestly means in a garbage-collected language.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.ratchet.destroy()
	Wipe(s.associated)
	s.associated = nil
	return nil
}

// CanSend reports whether a sending chain exists.
//
// The responder cannot send until the initiator's first message has arrived and
// turned the ratchet. That is inherent to the Double Ratchet, and the chat layer
// works with it by having the guest speak first.
func (s *Session) CanSend() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.ratchet.canSend()
}

// NeedsRekey reports that this side should prompt the peer for a reply so the
// DH ratchet can turn. See the constants above.
func (s *Session) NeedsRekey() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	return s.sentSinceStep >= RekeyAfterMessages || time.Since(s.lastStep) >= RekeyAfterInterval
}

// Steps reports how many DH ratchet steps this session has performed. It exists
// so tests can assert that ratcheting really happens rather than assuming it.
func (s *Session) Steps() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.steps
}

// Encrypt turns one plaintext message into one record.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrSessionClosed
	}

	h, messageKey, err := s.ratchet.next()
	if err != nil {
		return nil, err
	}
	defer Wipe(messageKey)

	key, nonce, err := messageKeys(messageKey)
	if err != nil {
		return nil, err
	}
	defer wipeAll(key, nonce)

	box, err := aead(key)
	if err != nil {
		return nil, err
	}

	headerBytes := h.encode()
	padded := pad(plaintext)
	defer Wipe(padded)

	record := make([]byte, 0, headerSize+len(padded)+tagSize)
	record = append(record, headerBytes...)
	record = box.Seal(record, nonce, padded, s.additionalData(headerBytes))

	s.sentSinceStep++
	return record, nil
}

// Decrypt turns one record back into one plaintext message.
//
// Every failure path leaves the session state EXACTLY as it was. The ratchet is
// advanced on a clone, and the clone is only adopted once the Poly1305 tag has
// verified, so a forged, replayed, reordered or truncated record cannot move a
// chain forward and cannot cause a later genuine message to be lost.
func (s *Session) Decrypt(record []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrSessionClosed
	}
	if len(record) < headerSize+tagSize {
		return nil, ErrMalformed
	}

	headerBytes := record[:headerSize]
	h, err := decodeHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	if h.version != byte(V2) {
		// A record that claims a version this build does not implement is
		// refused rather than parsed hopefully.
		return nil, ErrMalformed
	}

	speculative := s.ratchet.clone()
	messageKey, from, err := speculative.receive(h)
	if err != nil {
		speculative.destroy()
		return nil, err
	}

	defer Wipe(messageKey)

	key, nonce, kerr := messageKeys(messageKey)
	if kerr != nil {
		speculative.destroy()
		return nil, kerr
	}
	defer wipeAll(key, nonce)

	box, aerr := aead(key)
	if aerr != nil {
		speculative.destroy()
		return nil, aerr
	}

	padded, oerr := box.Open(nil, nonce, record[headerSize:], s.additionalData(headerBytes))
	if oerr != nil {
		// Discard the speculative state. This is the whole point of the clone:
		// an attacker who flips a bit, replays an old record, or forges a header
		// achieves nothing beyond one rejected message.
		speculative.destroy()
		return nil, ErrDecrypt
	}
	defer Wipe(padded)

	plaintext, perr := unpad(padded)
	if perr != nil {
		speculative.destroy()
		return nil, ErrDecrypt
	}
	out := append([]byte(nil), plaintext...)

	// Commit. The consumed message key is destroyed here, which is what stops
	// the same record ever decrypting twice.
	if from.ratchetPub != "" {
		speculative.forget(from)
	}
	stepped := speculative.steps != s.ratchet.steps
	s.ratchet.destroy()
	s.ratchet = speculative
	if stepped {
		s.steps = speculative.steps
		s.sentSinceStep = 0
		s.lastStep = time.Now()
	}
	return out, nil
}

// additionalData is AD0 || header. Callers hold s.mu.
func (s *Session) additionalData(headerBytes []byte) []byte {
	ad := make([]byte, 0, len(s.associated)+len(headerBytes))
	ad = append(ad, s.associated...)
	return append(ad, headerBytes...)
}

// WriteMessage encrypts a plaintext and writes it as one frame.
func (s *Session) WriteMessage(w io.Writer, plaintext []byte) error {
	record, err := s.Encrypt(plaintext)
	if err != nil {
		return err
	}
	return writeFrame(w, record)
}

// ReadMessage reads one frame and decrypts it.
func (s *Session) ReadMessage(r io.Reader) ([]byte, error) {
	record, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	return s.Decrypt(record)
}

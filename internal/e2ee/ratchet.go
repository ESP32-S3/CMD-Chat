package e2ee

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// The Double Ratchet, as published by Perrin and Marlinspike, over X25519,
// HKDF-SHA-256, HMAC-SHA-256 and ChaCha20-Poly1305.
//
// This is a straight implementation of that algorithm. Nothing here is a new
// ratchet design; the deviations from the specification's pseudocode are the
// choice of primitives, the domain-separation labels, and the bounds on the
// skipped-key store, all of which the specification leaves to the implementer.

// Ratchet limits.
const (
	// MaxSkip is the largest gap in one chain that will be tolerated in a
	// single step. A message claiming to be further ahead than this is
	// REJECTED rather than causing MaxSkip key derivations on demand — which is
	// what turns a ratchet into a CPU-exhaustion target.
	MaxSkip = 1000

	// MaxSkipStore bounds how many out-of-order message keys are held across
	// all chains. Beyond this the oldest are dropped, and the messages they
	// would have decrypted become undecryptable. Losing very old skipped
	// messages is better than an attacker growing this map without limit.
	MaxSkipStore = 2000
)

// Ratchet errors. The session layer collapses most of these into one opaque
// error before they reach a caller.
var (
	// ErrSkipTooLarge means a header claimed a gap beyond MaxSkip.
	ErrSkipTooLarge = errors.New("e2ee: message is too far ahead of the current chain")
	// ErrStaleMessage means the message key for this position no longer exists:
	// the message was already received (a replay or a duplicate), or it fell out
	// of the skipped-key store (too old).
	ErrStaleMessage = errors.New("e2ee: message is a duplicate, a replay, or too old to decrypt")
	// ErrDecrypt means the AEAD tag did not verify.
	ErrDecrypt = errors.New("e2ee: message failed authentication")
)

// headerSize is version(1) + ratchetPub(32) + pn(4) + n(4).
const headerSize = 1 + 32 + 4 + 4

// header is the authenticated, unencrypted preamble of every record.
type header struct {
	version    byte
	ratchetPub []byte
	pn         uint32
	n          uint32
}

func (h header) encode() []byte {
	out := make([]byte, 0, headerSize)
	out = append(out, h.version)
	out = append(out, h.ratchetPub...)
	out = appendU32(out, h.pn)
	return appendU32(out, h.n)
}

func decodeHeader(b []byte) (header, error) {
	if len(b) != headerSize {
		return header{}, ErrMalformed
	}
	h := header{version: b[0], ratchetPub: b[1:33]}
	h.pn = binary.BigEndian.Uint32(b[33:37])
	h.n = binary.BigEndian.Uint32(b[37:41])
	return h, nil
}

// skippedKey identifies one message key held for an out-of-order message.
type skippedKey struct {
	ratchetPub string // the raw 32 bytes, as a map-safe string
	n          uint32
}

// ratchet is the Double Ratchet state for one session.
//
// It is not safe for concurrent use; Session owns the lock.
type ratchet struct {
	rootKey []byte

	sendKey    *ecdh.PrivateKey // DHs
	receiveKey *ecdh.PublicKey  // DHr

	sendChain    []byte // CKs, nil until the first DH ratchet step
	receiveChain []byte // CKr, nil until the first message arrives

	sendCount    uint32 // Ns
	receiveCount uint32 // Nr
	previousSent uint32 // PN

	// skipped holds message keys for messages that arrived out of order, or
	// that have not arrived yet. Insertion order is tracked separately so the
	// store can be trimmed oldest-first without scanning.
	skipped map[skippedKey][]byte
	order   []skippedKey

	// steps counts DH ratchet steps. Session uses it to notice that a step
	// happened during a speculative decryption, and tests use it to assert that
	// the ratchet really turns rather than trusting that it does.
	steps uint64

	rand io.Reader
}

// kdfRootKey is the DH ratchet step: a fresh root key and a fresh chain key
// from the old root key and a new shared secret.
func kdfRootKey(rootKey, dh []byte) (newRoot, chain []byte, err error) {
	out := make([]byte, 2*keySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, dh, rootKey, []byte(labelRatchetRoot)), out); err != nil {
		return nil, nil, err
	}
	return out[:keySize], out[keySize:], nil
}

// kdfChainKey is the symmetric ratchet step. The two HMAC constants are what
// keep the message key and the next chain key independent: learning one message
// key reveals nothing about the chain it came from, because HMAC is a PRF and
// 0x01 and 0x02 are distinct inputs.
func kdfChainKey(chain []byte) (messageKey, nextChain []byte) {
	return hmacSHA256(chain, []byte{0x01}), hmacSHA256(chain, []byte{0x02})
}

// messageKeys expands one message key into the AEAD key and nonce for exactly
// one record.
//
// Deriving the nonce from the message key rather than from a counter is the
// reason CMDC1 cannot reuse a nonce under a key: the message key is unique per
// (chain, index) by construction, so the (key, nonce) pair is unique too, and no
// counter reset or state rollback can produce a collision.
func messageKeys(messageKey []byte) (key, nonce []byte, err error) {
	out := make([]byte, keySize+nonceSize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, messageKey, nil, []byte(labelMessageKeys)), out); err != nil {
		return nil, nil, err
	}
	return out[:keySize], out[keySize:], nil
}

// newRatchetInitiator sets up the side that dialled.
//
// Per the specification, the initiator generates a fresh ratchet key pair
// immediately and performs one DH ratchet step against the responder's
// handshake ephemeral, so its first message already carries a new ratchet public
// key.
func newRatchetInitiator(rootKey []byte, peerRatchet *ecdh.PublicKey, random io.Reader) (*ratchet, error) {
	sendKey, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, err
	}
	shared, err := sendKey.ECDH(peerRatchet)
	if err != nil {
		return nil, err
	}
	defer Wipe(shared)

	newRoot, chain, err := kdfRootKey(rootKey, shared)
	if err != nil {
		return nil, err
	}
	Wipe(rootKey)

	return &ratchet{
		rootKey:    newRoot,
		sendKey:    sendKey,
		receiveKey: peerRatchet,
		sendChain:  chain,
		skipped:    map[skippedKey][]byte{},
		rand:       random,
	}, nil
}

// newRatchetResponder sets up the side that accepted.
//
// It keeps its handshake ephemeral as the initial ratchet key pair and has no
// sending chain until the initiator's first message arrives and turns the
// ratchet. That is the specification's asymmetry, not an oversight: the
// responder cannot derive a sending chain before it knows the initiator's
// ratchet public key.
func newRatchetResponder(rootKey []byte, ephemeral *ecdh.PrivateKey, random io.Reader) *ratchet {
	return &ratchet{
		rootKey: rootKey,
		sendKey: ephemeral,
		skipped: map[skippedKey][]byte{},
		rand:    random,
	}
}

// canSend reports whether a sending chain exists yet.
func (r *ratchet) canSend() bool { return r.sendChain != nil }

// next produces the header and message key for the next outgoing message.
func (r *ratchet) next() (header, []byte, error) {
	if !r.canSend() {
		return header{}, nil, errors.New("e2ee: cannot send before the peer's first message")
	}
	if r.sendCount == ^uint32(0) {
		// A chain that has run to 2^32 messages must not wrap: wrapping would
		// restart the counters while the peer's view kept climbing.
		return header{}, nil, errors.New("e2ee: sending chain exhausted")
	}
	messageKey, nextChain := kdfChainKey(r.sendChain)
	Wipe(r.sendChain)
	r.sendChain = nextChain

	h := header{
		version:    byte(V1),
		ratchetPub: r.sendKey.PublicKey().Bytes(),
		pn:         r.previousSent,
		n:          r.sendCount,
	}
	r.sendCount++
	return h, messageKey, nil
}

// step performs a DH ratchet step against a newly seen peer ratchet key.
func (r *ratchet) step(peerRatchet *ecdh.PublicKey) error {
	r.previousSent = r.sendCount
	r.sendCount = 0
	r.receiveCount = 0
	r.receiveKey = peerRatchet

	shared, err := r.sendKey.ECDH(peerRatchet)
	if err != nil {
		return ErrMalformed
	}
	newRoot, receiveChain, err := kdfRootKey(r.rootKey, shared)
	Wipe(shared)
	if err != nil {
		return err
	}
	Wipe(r.rootKey)
	wipeAll(r.receiveChain)
	r.rootKey, r.receiveChain = newRoot, receiveChain

	// A fresh sending key pair is what actually delivers post-compromise
	// security: from here on, an attacker holding the previous state cannot
	// derive the new root key without this private key, which it has never seen.
	sendKey, err := ecdh.X25519().GenerateKey(r.rand)
	if err != nil {
		return err
	}
	shared, err = sendKey.ECDH(peerRatchet)
	if err != nil {
		return ErrMalformed
	}
	newRoot, sendChain, err := kdfRootKey(r.rootKey, shared)
	Wipe(shared)
	if err != nil {
		return err
	}
	Wipe(r.rootKey)
	wipeAll(r.sendChain)
	r.rootKey, r.sendChain, r.sendKey = newRoot, sendChain, sendKey
	r.steps++
	return nil
}

// remember stores a skipped message key, trimming the store if needed.
func (r *ratchet) remember(k skippedKey, messageKey []byte) {
	if _, exists := r.skipped[k]; !exists {
		r.order = append(r.order, k)
	}
	r.skipped[k] = messageKey

	for len(r.order) > MaxSkipStore {
		oldest := r.order[0]
		r.order = r.order[1:]
		if key, ok := r.skipped[oldest]; ok {
			Wipe(key)
			delete(r.skipped, oldest)
		}
	}
}

// forget removes a skipped key once it has been used. Deleting it is the replay
// protection: the same ciphertext can never be decrypted twice, because the only
// copy of the key is destroyed on first use and the chain has already moved past
// the point where it could be recomputed.
func (r *ratchet) forget(k skippedKey) {
	if key, ok := r.skipped[k]; ok {
		Wipe(key)
		delete(r.skipped, k)
		for i, candidate := range r.order {
			if candidate == k {
				r.order = append(r.order[:i], r.order[i+1:]...)
				break
			}
		}
	}
}

// skipTo derives and stores message keys up to (but not including) target in the
// current receiving chain.
func (r *ratchet) skipTo(target uint32) error {
	if r.receiveChain == nil {
		return nil
	}
	if target < r.receiveCount {
		return nil
	}
	if target-r.receiveCount > MaxSkip {
		return ErrSkipTooLarge
	}
	pub := string(r.receiveKey.Bytes())
	for r.receiveCount < target {
		messageKey, nextChain := kdfChainKey(r.receiveChain)
		Wipe(r.receiveChain)
		r.receiveChain = nextChain
		r.remember(skippedKey{ratchetPub: pub, n: r.receiveCount}, messageKey)
		r.receiveCount++
	}
	return nil
}

// receive resolves the message key for an incoming header, advancing the ratchet
// as required.
//
// It may mutate ratchet state, so the caller MUST only call it on a copy unless
// it is prepared for a forged header to have moved the state. Session does
// exactly that: it works on a clone and commits only after the AEAD tag has
// verified. That is what makes a modified or forged record leave the session
// untouched.
func (r *ratchet) receive(h header) ([]byte, skippedKey, error) {
	peerRatchet, err := ecdh.X25519().NewPublicKey(h.ratchetPub)
	if err != nil {
		return nil, skippedKey{}, ErrMalformed
	}
	key := skippedKey{ratchetPub: string(h.ratchetPub), n: h.n}

	// An out-of-order message whose key we already derived.
	if messageKey, ok := r.skipped[key]; ok {
		return messageKey, key, nil
	}

	newChain := r.receiveKey == nil || !r.receiveKey.Equal(peerRatchet)
	if newChain {
		// Before turning the ratchet, finish the chain we are leaving, so
		// messages still in flight from it remain decryptable.
		if err := r.skipTo(h.pn); err != nil {
			return nil, skippedKey{}, err
		}
		if err := r.step(peerRatchet); err != nil {
			return nil, skippedKey{}, err
		}
	}

	if h.n < r.receiveCount {
		// Already past this index and the key is not in the store: it was
		// consumed (replay or duplicate) or evicted (too old).
		return nil, skippedKey{}, ErrStaleMessage
	}
	if err := r.skipTo(h.n); err != nil {
		return nil, skippedKey{}, err
	}

	messageKey, nextChain := kdfChainKey(r.receiveChain)
	Wipe(r.receiveChain)
	r.receiveChain = nextChain
	r.receiveCount++
	return messageKey, skippedKey{}, nil
}

// clone makes a deep-enough copy for speculative decryption.
//
// The X25519 keys are immutable values and are shared by reference. Every byte
// slice that receive() may overwrite is copied, so committing means swapping the
// clone in and discarding means dropping it.
func (r *ratchet) clone() *ratchet {
	out := &ratchet{
		rootKey:      cloneBytes(r.rootKey),
		sendKey:      r.sendKey,
		receiveKey:   r.receiveKey,
		sendChain:    cloneBytes(r.sendChain),
		receiveChain: cloneBytes(r.receiveChain),
		sendCount:    r.sendCount,
		receiveCount: r.receiveCount,
		previousSent: r.previousSent,
		steps:        r.steps,
		skipped:      make(map[skippedKey][]byte, len(r.skipped)),
		order:        append([]skippedKey(nil), r.order...),
		rand:         r.rand,
	}
	for k, v := range r.skipped {
		out.skipped[k] = cloneBytes(v)
	}
	return out
}

// destroy wipes every secret the ratchet holds.
func (r *ratchet) destroy() {
	wipeAll(r.rootKey, r.sendChain, r.receiveChain)
	for k, v := range r.skipped {
		Wipe(v)
		delete(r.skipped, k)
	}
	r.order = nil
	r.rootKey, r.sendChain, r.receiveChain = nil, nil, nil
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

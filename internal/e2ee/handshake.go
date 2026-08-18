package e2ee

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// Version is a CMDC1 protocol version as it appears on the wire.
type Version uint16

// V1 is the first — and currently only — CMDC1 version.
const V1 Version = 1

// SupportedVersions lists what this build will speak, most preferred first.
//
// A version that is not in this list is refused outright. There is no
// "compatibility mode", no fallback to the pre-CMDC1 plaintext-inside-TLS
// handshake, and no way for a peer to talk this build down to one: the offered
// list and the chosen version are both inside the transcript that both sides
// sign, so tampering is detected before any message key exists.
var SupportedVersions = []Version{V1}

// Errors a caller may want to distinguish. Everything else is deliberately
// opaque.
var (
	// ErrNoCommonVersion means the peer offered no version this build accepts.
	ErrNoCommonVersion = errors.New("e2ee: no mutually supported protocol version")
	// ErrDowngrade means the peer selected a version it was never offered.
	ErrDowngrade = errors.New("e2ee: peer selected a protocol version that was not offered")
	// ErrNoChannelBinding means the caller did not supply TLS exporter material.
	ErrNoChannelBinding = errors.New("e2ee: refusing to run without TLS channel binding")
	// ErrAuthentication covers every failure to prove an identity: a bad
	// signature, a bad key-confirmation MAC, an ID that does not match its key,
	// or a peer that is not the expected one. They are one error on purpose, so
	// a prober learns nothing from which check failed.
	ErrAuthentication = errors.New("e2ee: peer identity authentication failed")
	// ErrUntrustedKey means the peer proved an identity, but the trust store
	// refused it — nearly always because a known ID presented a new key.
	ErrUntrustedKey = errors.New("e2ee: peer identity key is not trusted")
)

// Credentials is the local side's long-term identity, plus the display label it
// wants to present.
//
// Sign is a function rather than a private key so that the private key never has
// to be copied into this package, and so a future hardware- or OS-held key can
// be dropped in without changing the protocol.
type Credentials struct {
	ID        string
	PublicKey ed25519.PublicKey
	Sign      func(message []byte) []byte
	Nickname  string
}

func (c Credentials) valid() error {
	if len(c.PublicKey) != ed25519.PublicKeySize || c.Sign == nil {
		return errors.New("e2ee: incomplete credentials")
	}
	if !usableIdentityKey(c.PublicKey) {
		return errors.New("e2ee: local identity key is a small-order point")
	}
	if c.ID != identity.DeriveID(c.PublicKey) {
		return errors.New("e2ee: local ID does not match local public key")
	}
	return nil
}

// TrustPolicy decides whether a CRYPTOGRAPHICALLY PROVEN peer identity is
// acceptable.
//
// It is called only after the signature and key-confirmation MAC have verified
// and after the ID has been checked against the public key, so an implementation
// may assume the peer really does hold the private key for what it presented.
// The question it answers is the trust-on-first-use one: is this the key we saw
// for this ID last time?
//
// Returning an error aborts the handshake. Aborting is the ONLY option offered:
// there is no callback shape here that lets a caller accept a changed key
// silently.
type TrustPolicy interface {
	Authorize(id string, publicKey ed25519.PublicKey) error
}

// TrustPolicyFunc adapts a function to TrustPolicy.
type TrustPolicyFunc func(id string, publicKey ed25519.PublicKey) error

// Authorize implements TrustPolicy.
func (f TrustPolicyFunc) Authorize(id string, publicKey ed25519.PublicKey) error {
	return f(id, publicKey)
}

// Config parameterises one handshake.
type Config struct {
	// Credentials is this side's identity. Required.
	Credentials Credentials

	// ChannelBinding is TLS exporter material for the underlying connection,
	// from TLSChannelBinding. Required; a zero-length value is refused.
	ChannelBinding []byte

	// Trust vets the peer's proven identity. Required.
	Trust TrustPolicy

	// ExpectPeerID, when set, requires the peer to authenticate as exactly this
	// CMD-Chat ID. The guest sets it to the ID it looked up, so a phonebook that
	// returns the wrong peer is caught here rather than becoming a conversation
	// with a stranger.
	ExpectPeerID string

	// Versions overrides SupportedVersions. Tests use it to simulate an old
	// build; production leaves it nil.
	Versions []Version

	// Rand overrides crypto/rand. Tests use it; production leaves it nil.
	Rand io.Reader
}

func (c *Config) versions() []Version {
	if len(c.Versions) > 0 {
		return c.Versions
	}
	return SupportedVersions
}

func (c *Config) random() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Config) validate() error {
	if err := c.Credentials.valid(); err != nil {
		return err
	}
	if len(c.ChannelBinding) == 0 {
		return ErrNoChannelBinding
	}
	if c.Trust == nil {
		return errors.New("e2ee: no trust policy supplied")
	}
	if len(c.versions()) == 0 {
		return ErrNoCommonVersion
	}
	return nil
}

// PeerInfo describes the far side of a completed handshake.
type PeerInfo struct {
	// ID is proven. It is the only field here that means anything about who the
	// peer is.
	ID string

	// PublicKey is the Ed25519 key that proved ID.
	PublicKey ed25519.PublicKey

	// Nickname is self-chosen. It is authenticated in the sense that the peer
	// really did send it and nobody altered it in flight — and it is still just
	// a label the peer picked for itself. Never use it to decide who someone is.
	Nickname string

	// Version is the CMDC1 version both sides agreed on.
	Version Version
}

// authPayload is the plaintext inside C2 and C3.
type authPayload struct {
	identityPub []byte
	id          string
	signature   []byte
	mac         []byte
	nickname    string
}

func (p authPayload) encode() []byte {
	out := make([]byte, 0, 32+4+len(p.id)+64+32+4+len(p.nickname))
	out = append(out, p.identityPub...)
	out = lengthPrefix(out, []byte(p.id))
	out = append(out, p.signature...)
	out = append(out, p.mac...)
	return lengthPrefix(out, []byte(p.nickname))
}

func decodeAuthPayload(b []byte) (authPayload, error) {
	r := &reader{b: b}
	var p authPayload
	p.identityPub = r.take(ed25519.PublicKeySize)
	p.id = string(r.lp())
	p.signature = r.take(ed25519.SignatureSize)
	p.mac = r.take(keySize)
	p.nickname = string(r.lp())
	if err := r.done(); err != nil {
		return authPayload{}, err
	}
	return p, nil
}

// MaxNicknameBytes bounds the label a peer can put on another person's screen.
// The chat layer sanitises it further; this stops an oversized one reaching that
// code at all.
const MaxNicknameBytes = 256

// MaxIDBytes bounds the claimed CMD-Chat ID. Real IDs are 19 bytes.
const MaxIDBytes = 64

// handshakeKeys are the four single-use keys derived from the ephemeral DH.
type handshakeKeys struct {
	prk      []byte
	respKey  []byte
	initKey  []byte
	respMAC  []byte
	initMAC  []byte
	sharedDH []byte
}

func (k *handshakeKeys) wipe() {
	// prk is kept until the session keys are derived; the caller wipes it then.
	wipeAll(k.respKey, k.initKey, k.respMAC, k.initMAC, k.sharedDH)
}

// deriveHandshakeKeys runs the handshake key schedule described in doc.go.
func deriveHandshakeKeys(shared, th2 []byte) (*handshakeKeys, error) {
	k := &handshakeKeys{sharedDH: shared}
	k.prk = hkdfExtract(th2, shared)

	var err error
	if k.respKey, err = hkdfExpandLabel(k.prk, labelHandshakeKeyResponder, keySize); err != nil {
		return nil, err
	}
	if k.initKey, err = hkdfExpandLabel(k.prk, labelHandshakeKeyInitiator, keySize); err != nil {
		return nil, err
	}
	if k.respMAC, err = hkdfExpandLabel(k.prk, labelHandshakeMACResponder, keySize); err != nil {
		return nil, err
	}
	if k.initMAC, err = hkdfExpandLabel(k.prk, labelHandshakeMACInitiator, keySize); err != nil {
		return nil, err
	}
	return k, nil
}

// zeroNonce is the nonce used for the two handshake AEAD operations.
//
// This is safe ONLY because respKey and initKey each encrypt exactly one
// ciphertext, ever, and are derived from a transcript that includes both fresh
// ephemeral keys and two 32-byte randoms. It must not be copied to the record
// layer, which derives a fresh key and nonce for every single message.
var zeroNonce = make([]byte, nonceSize)

// sealAuth builds and encrypts an AuthPayload.
func sealAuth(cfg *Config, key, macKey, transcript []byte, sigLabel, macLabel string) ([]byte, error) {
	ctx := context(sigLabel, transcript, cfg.Credentials.PublicKey, cfg.Credentials.ID)
	payload := authPayload{
		identityPub: cfg.Credentials.PublicKey,
		id:          cfg.Credentials.ID,
		signature:   cfg.Credentials.Sign(ctx),
		mac:         hmacSHA256(macKey, context(macLabel, transcript, cfg.Credentials.PublicKey, cfg.Credentials.ID)),
		nickname:    cfg.Credentials.Nickname,
	}
	if len(payload.signature) != ed25519.SignatureSize {
		return nil, errors.New("e2ee: signer returned a malformed signature")
	}
	box, err := aead(key)
	if err != nil {
		return nil, err
	}
	return box.Seal(nil, zeroNonce, payload.encode(), transcript), nil
}

// openAuth decrypts and fully verifies a peer's AuthPayload.
//
// Order matters. The AEAD tag is checked first (by Open), so nothing below ever
// runs on attacker-chosen plaintext. Then the structural bounds, then the
// ID-to-key binding, then the signature, then the confirmation MAC, and only
// then the trust store. Every failure before the trust store returns the same
// ErrAuthentication.
func openAuth(cfg *Config, ciphertext, key, macKey, transcript []byte, sigLabel, macLabel string) (PeerInfo, error) {
	box, err := aead(key)
	if err != nil {
		return PeerInfo{}, err
	}
	plaintext, err := box.Open(nil, zeroNonce, ciphertext, transcript)
	if err != nil {
		return PeerInfo{}, ErrAuthentication
	}
	defer Wipe(plaintext)

	payload, err := decodeAuthPayload(plaintext)
	if err != nil {
		return PeerInfo{}, ErrAuthentication
	}
	if len(payload.id) == 0 || len(payload.id) > MaxIDBytes || len(payload.nickname) > MaxNicknameBytes {
		return PeerInfo{}, ErrAuthentication
	}

	// Reject small-order and non-canonical keys before anything verifies against
	// them. crypto/ed25519 will happily accept an all-zero signature under the
	// all-zero public key; see smallorder.go.
	pub := ed25519.PublicKey(append([]byte(nil), payload.identityPub...))
	if !usableIdentityKey(pub) {
		return PeerInfo{}, ErrAuthentication
	}

	// The ID must be the one this public key derives. Without this a peer could
	// present someone else's ID beside its own key.
	if identity.DeriveID(pub) != payload.id {
		return PeerInfo{}, ErrAuthentication
	}

	// Signature over the transcript: authenticates the ephemeral keys, the
	// channel binding, the version negotiation and this identity, together.
	if !ed25519.Verify(pub, context(sigLabel, transcript, pub, payload.id), payload.signature) {
		return PeerInfo{}, ErrAuthentication
	}

	// SIGMA key confirmation: proves the signer is the same party that holds
	// the DH secret. This is what rules out unknown-key-share, where an
	// attacker relays a genuine signature to bind someone else's identity to a
	// key exchange they never took part in.
	want := hmacSHA256(macKey, context(macLabel, transcript, pub, payload.id))
	if !hmac.Equal(want, payload.mac) {
		return PeerInfo{}, ErrAuthentication
	}

	// The peer is now proven. Is it the peer we came here to talk to?
	if cfg.ExpectPeerID != "" && cfg.ExpectPeerID != payload.id {
		return PeerInfo{}, fmt.Errorf("%w: identity mismatch, expected %s but the peer proved %s", ErrAuthentication, cfg.ExpectPeerID, payload.id)
	}
	if err := cfg.Trust.Authorize(payload.id, pub); err != nil {
		return PeerInfo{}, fmt.Errorf("%w: %v", ErrUntrustedKey, err)
	}

	return PeerInfo{ID: payload.id, PublicKey: pub, Nickname: payload.nickname}, nil
}

// Initiate runs the CMDC1 handshake as the initiator (the guest, the side that
// dialled) and returns a ready session.
//
// On any error the caller must close the underlying connection. This function
// never returns a partially usable session.
func Initiate(rw io.ReadWriter, cfg Config) (*Session, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	ephemeral, err := ecdh.X25519().GenerateKey(cfg.random())
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(cfg.random(), nonce); err != nil {
		return nil, err
	}

	offered := cfg.versions()
	m1 := make([]byte, 0, 3+2*len(offered)+64)
	m1 = append(m1, msgInit, byte(len(offered)))
	for _, v := range offered {
		m1 = appendU16(m1, uint16(v))
	}
	m1 = append(m1, ephemeral.PublicKey().Bytes()...)
	m1 = append(m1, nonce...)
	if err := writeFrame(rw, m1); err != nil {
		return nil, err
	}

	th0 := hashTranscript([]byte(labelTranscript), cfg.ChannelBinding)
	th1 := hashTranscript(th0, m1)

	m2, err := readFrame(rw)
	if err != nil {
		return nil, err
	}
	// M2 header: type(1) | version(2) | ephemeral(32) | random(32).
	const m2HeaderLen = 1 + 2 + 32 + 32
	if len(m2) < m2HeaderLen {
		return nil, ErrMalformed
	}
	r := &reader{b: m2}
	if r.u8() != msgResp {
		return nil, ErrMalformed
	}
	chosen := Version(r.u16())
	peerEphemeral := r.take(32)
	_ = r.take(32) // responder random: covered by the transcript, not read directly
	c2 := r.lp()
	if err := r.done(); err != nil {
		return nil, err
	}

	// The responder must have picked one of OUR offers. This check is belt to
	// the transcript's braces: even if it somehow passed, the signature over
	// th2 would not verify, because th1 covers the list we actually sent.
	if !containsVersion(offered, chosen) {
		return nil, fmt.Errorf("%w: %d", ErrDowngrade, chosen)
	}
	if !containsVersion(SupportedVersions, chosen) {
		return nil, fmt.Errorf("%w: %d", ErrNoCommonVersion, chosen)
	}

	remote, err := ecdh.X25519().NewPublicKey(peerEphemeral)
	if err != nil {
		return nil, ErrMalformed
	}
	// ECDH here rejects a low-order peer key by returning an error on an
	// all-zero shared secret, so a forced-zero-key attack fails in crypto/ecdh
	// rather than needing a check of our own.
	shared, err := ephemeral.ECDH(remote)
	if err != nil {
		return nil, ErrMalformed
	}

	th2 := hashTranscript(th1, m2[:m2HeaderLen])
	keys, err := deriveHandshakeKeys(shared, th2)
	if err != nil {
		return nil, err
	}
	defer keys.wipe()

	peer, err := openAuth(&cfg, c2, keys.respKey, keys.respMAC, th2, labelSignatureResponder, labelConfirmResponder)
	if err != nil {
		return nil, err
	}
	peer.Version = chosen

	th3 := hashTranscript(th2, c2)
	c3, err := sealAuth(&cfg, keys.initKey, keys.initMAC, th3, labelSignatureInitiator, labelConfirmInitiator)
	if err != nil {
		return nil, err
	}
	m3 := append([]byte{msgFinish}, appendU32(nil, uint32(len(c3)))...)
	m3 = append(m3, c3...)
	if err := writeFrame(rw, m3); err != nil {
		return nil, err
	}

	th4 := hashTranscript(th3, c3)
	session, err := newSession(keys.prk, th4, peer, roleInitiator, remote, nil, cfg.random())
	if err != nil {
		return nil, err
	}

	// M4: the priming record.
	//
	// The Double Ratchet responder has no sending chain until it has seen the
	// initiator's first ratchet public key — that asymmetry is inherent to the
	// algorithm. CMD-Chat's host speaks first at the application layer (it sends
	// "hello"), so without this the host would be unable to say anything until
	// the guest did.
	//
	// The priming record carries an empty plaintext. It costs one frame, it
	// turns the responder's ratchet, and it doubles as confirmation that the
	// record layer itself agrees on keys: if anything about the key schedule
	// differed between the two sides, this is where it fails, before a single
	// user message exists.
	if err := session.WriteMessage(rw, nil); err != nil {
		_ = session.Close()
		return nil, err
	}
	return session, nil
}

// Respond runs the CMDC1 handshake as the responder (the host, the side that
// accepted) and returns a ready session.
func Respond(rw io.ReadWriter, cfg Config) (*Session, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	m1, err := readFrame(rw)
	if err != nil {
		return nil, err
	}
	r := &reader{b: m1}
	if r.u8() != msgInit {
		return nil, ErrMalformed
	}
	count := int(r.u8())
	offered := make([]Version, 0, count)
	for i := 0; i < count; i++ {
		offered = append(offered, Version(r.u16()))
	}
	peerEphemeral := r.take(32)
	_ = r.take(32) // initiator random
	if err := r.done(); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrNoCommonVersion
	}

	// Choose by OUR preference order, not the peer's, so a peer cannot steer us
	// towards the weakest version we happen to still support.
	chosen, ok := selectVersion(cfg.versions(), offered)
	if !ok {
		return nil, ErrNoCommonVersion
	}

	remote, err := ecdh.X25519().NewPublicKey(peerEphemeral)
	if err != nil {
		return nil, ErrMalformed
	}
	ephemeral, err := ecdh.X25519().GenerateKey(cfg.random())
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(remote)
	if err != nil {
		return nil, ErrMalformed
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(cfg.random(), nonce); err != nil {
		return nil, err
	}

	th0 := hashTranscript([]byte(labelTranscript), cfg.ChannelBinding)
	th1 := hashTranscript(th0, m1)

	m2Header := make([]byte, 0, 1+2+32+32)
	m2Header = append(m2Header, msgResp)
	m2Header = appendU16(m2Header, uint16(chosen))
	m2Header = append(m2Header, ephemeral.PublicKey().Bytes()...)
	m2Header = append(m2Header, nonce...)

	th2 := hashTranscript(th1, m2Header)
	keys, err := deriveHandshakeKeys(shared, th2)
	if err != nil {
		return nil, err
	}
	defer keys.wipe()

	c2, err := sealAuth(&cfg, keys.respKey, keys.respMAC, th2, labelSignatureResponder, labelConfirmResponder)
	if err != nil {
		return nil, err
	}
	m2 := append(append([]byte(nil), m2Header...), appendU32(nil, uint32(len(c2)))...)
	m2 = append(m2, c2...)
	if err := writeFrame(rw, m2); err != nil {
		return nil, err
	}

	th3 := hashTranscript(th2, c2)

	m3, err := readFrame(rw)
	if err != nil {
		return nil, err
	}
	r = &reader{b: m3}
	if r.u8() != msgFinish {
		return nil, ErrMalformed
	}
	c3 := r.lp()
	if err := r.done(); err != nil {
		return nil, err
	}

	peer, err := openAuth(&cfg, c3, keys.initKey, keys.initMAC, th3, labelSignatureInitiator, labelConfirmInitiator)
	if err != nil {
		return nil, err
	}
	peer.Version = chosen

	th4 := hashTranscript(th3, c3)
	session, err := newSession(keys.prk, th4, peer, roleResponder, nil, ephemeral, cfg.random())
	if err != nil {
		return nil, err
	}

	// Consume the initiator's priming record; see the note in Initiate. It must
	// be empty: anything else means the peer is not speaking this protocol, and
	// a session that carried on regardless would silently drop a real message.
	primer, err := session.ReadMessage(rw)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	if len(primer) != 0 {
		_ = session.Close()
		return nil, ErrMalformed
	}
	return session, nil
}

func containsVersion(list []Version, v Version) bool {
	for _, candidate := range list {
		if candidate == v {
			return true
		}
	}
	return false
}

// selectVersion picks the first of ours that the peer also offered.
func selectVersion(ours, theirs []Version) (Version, bool) {
	for _, v := range ours {
		if containsVersion(theirs, v) {
			return v, true
		}
	}
	return 0, false
}

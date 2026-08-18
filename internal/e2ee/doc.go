// Package e2ee implements the CMD-Chat application-layer end-to-end encrypted
// channel: protocol CMDC1.
//
// It sits ABOVE TLS 1.3 and does not replace it. TLS protects the hop; CMDC1
// protects the conversation. Everything CMDC1 writes is opaque ciphertext to
// the relay, to Cloudflare, to an ISP, and to anyone who has terminated or
// broken the TLS session.
//
// # Why this construction
//
// The requirement is a two-party, INTERACTIVE session: both endpoints are
// online at the same time, because CMD-Chat has no offline message delivery and
// no message store. That rules X3DH out — X3DH exists to let Alice send to an
// offline Bob using prekeys published to a server, and CMD-Chat has neither the
// server role nor the offline case. It also rules MLS out: MLS solves
// continuous group key agreement for large, membership-changing groups, and a
// CMD-Chat room is a star of independent two-party links around a human host.
//
// What is left is the well-trodden interactive pattern:
//
//	SIGMA-I (sign-and-mac authenticated ephemeral DH)  ->  Double Ratchet
//
// SIGMA is the design underneath IKEv2 and, in its signed-transcript form,
// underneath TLS 1.3's own authentication. It is equivalent in shape to the
// Noise "IK"/"XX" patterns, except that it authenticates with signatures over a
// transcript rather than with static-static DH, which is what lets CMD-Chat keep
// its EXISTING Ed25519 identity keys untouched and avoid converting Ed25519 keys
// to X25519. No key is used for two algorithms.
//
// The Double Ratchet is used as published (Signal's specification, Perrin &
// Marlinspike) and is not modified. No new ratchet is invented here.
//
// # Primitives
//
// All from the Go standard library or golang.org/x/crypto. Nothing in this
// package implements a cryptographic primitive.
//
//	Identity signatures   Ed25519                        crypto/ed25519
//	Key agreement         X25519                         crypto/ecdh
//	Hash / transcript     SHA-256                        crypto/sha256
//	KDF                   HKDF-SHA-256                   golang.org/x/crypto/hkdf
//	Chain KDF             HMAC-SHA-256                   crypto/hmac
//	AEAD                  ChaCha20-Poly1305 (256/96)     golang.org/x/crypto/chacha20poly1305
//	Randomness            crypto/rand
//
// # Channel binding
//
// The whole handshake transcript starts from a TLS 1.3 exporter value
// (RFC 5705 / RFC 8446 §7.5) taken from the underlying connection:
//
//	binding = TLS-Exporter("EXPORTER-CMD-Chat-CMDC1-channel-binding", nil, 32)
//
// Both endpoints hash it into th0 and both sign a transcript that contains it.
// A man-in-the-middle who terminates TLS on both sides necessarily has TWO
// different TLS sessions and therefore two different exporter values, so the
// signatures it forwards do not verify. This closes the authentication-relay
// break described as W1 in docs/SECURITY-BASELINE.md.
//
// A session with no channel binding is REFUSED. There is no "binding optional"
// mode and no downgrade to one.
//
// # Notation
//
//	lp(x)      = uint32be(len(x)) || x          ("length-prefixed")
//	label(s)   = the ASCII bytes of s
//	||         = concatenation
//	H(x)       = SHA-256(x)
//
// All integers on the wire are big-endian. The transcript never hashes a
// variable-length field without a length prefix, so no two distinct transcripts
// can produce the same hash input.
//
// # Handshake: three flights
//
// The guest (the side that dialled) is the INITIATOR. The host (the side that
// accepted) is the RESPONDER. This matches the existing CMD-Chat roles exactly.
//
//	Initiator                                                     Responder
//	---------                                                     ---------
//	M1  type=1 | versions[] | e_i (32) | rand_i (32)         ->
//	                                                <-   M2  type=2 | version | e_r (32) | rand_r (32) | lp(C2)
//	M3  type=3 | lp(C3)                                      ->
//	M4  priming record (empty plaintext)                     ->
//
// M1 offers every protocol version this build supports, most preferred first.
// M2 names the single version chosen. Both the offered list and the choice are
// inside the transcript that both sides sign, so an attacker who strips a
// version from M1 to force a weaker one is detected when the signatures are
// checked. Unknown or unsupported versions fail closed.
//
// # Transcript
//
//	th0 = H( label("CMD-CHAT-E2EE v1 transcript") || lp(binding) )
//	th1 = H( th0 || lp(M1) )                     // M1 in full, as written
//	th2 = H( th1 || lp(M2header) )               // M2 up to but excluding lp(C2)
//	th3 = H( th2 || lp(C2) )
//	th4 = H( th3 || lp(C3) )
//
// C2 and C3 are AEAD ciphertexts, so hashing the ciphertext also commits to the
// plaintext under the key: this avoids the circularity of trying to sign a
// payload that contains its own signature.
//
// # Handshake key schedule
//
//	DH  = X25519(e_i, e_r)      // crypto/ecdh rejects low-order results itself
//	PRK = HKDF-Extract(SHA-256, salt = th2, ikm = DH)
//
//	k_r  = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs responder key",  32)
//	k_i  = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs initiator key",  32)
//	m_r  = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs responder mac",  32)
//	m_i  = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs initiator mac",  32)
//
// k_r encrypts C2 and k_i encrypts C3. Each of those keys encrypts exactly one
// ciphertext in the lifetime of the session, so both use the all-zero 96-bit
// nonce. That is safe precisely because the key is single-use; it is NOT a
// pattern that may be copied to the record layer, which derives a fresh key and
// nonce per message.
//
//	C2 = AEAD-Seal(k_r, nonce=0^12, ad = th2, plaintext = AuthPayload_r)
//	C3 = AEAD-Seal(k_i, nonce=0^12, ad = th3, plaintext = AuthPayload_i)
//
// # AuthPayload
//
//	identityPub  [32]   Ed25519 public key
//	id           lp     the "cc-…" CMD-Chat ID string
//	signature    [64]   Ed25519
//	mac          [32]   HMAC-SHA-256
//	nickname     lp     display label, authenticated but NOT an identity claim
//
// The responder signs and MACs over th2; the initiator over th3.
//
//	sig_r = Ed25519-Sign(sk_r, label("CMD-CHAT-E2EE v1 responder signature") || 0x00 || th2 || identityPub_r || lp(id_r))
//	mac_r = HMAC-SHA-256(m_r,  label("CMD-CHAT-E2EE v1 responder confirm")   || 0x00 || th2 || identityPub_r || lp(id_r))
//
//	sig_i = Ed25519-Sign(sk_i, label("CMD-CHAT-E2EE v1 initiator signature") || 0x00 || th3 || identityPub_i || lp(id_i))
//	mac_i = HMAC-SHA-256(m_i,  label("CMD-CHAT-E2EE v1 initiator confirm")   || 0x00 || th3 || identityPub_i || lp(id_i))
//
// The signature is what authenticates the ephemeral keys to a long-term
// identity. The MAC is SIGMA's key-confirmation step: it proves the signer is
// the same party that holds the DH secret, which is what rules out
// unknown-key-share. Signing one's own identity key and ID as well ties the
// three together explicitly.
//
// Because the initiator signs th3, and th3 covers C2 which covers the
// responder's identity, both sides finish with agreement on the FULL transcript
// including WHO the other party is. Neither can be tricked about which stable
// identity it authenticated.
//
// The verifier additionally recomputes "cc-" || base32(SHA-256(identityPub)[0:10])
// and requires it to equal the claimed ID, so an ID cannot be detached from its
// key, and it consults the trust-on-first-use store: a KNOWN id presenting a
// DIFFERENT public key aborts the handshake. There is no prompt and no
// "accept anyway" path.
//
// The nickname is inside the AEAD and inside the transcript, so it cannot be
// altered in flight — but it is still self-chosen and proves nothing about who
// the peer is. Only the ID is proven.
//
// # Session keys
//
//	th4 = H( th3 || lp(C3) )
//	RK0 = HKDF-Expand(PRK, label("CMD-CHAT-E2EE v1 root key")        || th4, 32)
//	AD0 = HKDF-Expand(PRK, label("CMD-CHAT-E2EE v1 associated data") || th4, 32)
//
// RK0 seeds the Double Ratchet. AD0 is a 32-byte session tag mixed into the
// associated data of every record, so a ciphertext captured in one session can
// never be replayed into another session between the same two people — the AEAD
// check fails before any state is touched.
//
// # M4, the priming record
//
// The Double Ratchet responder has no sending chain until it has seen the
// initiator's first ratchet public key. CMD-Chat's host speaks first at the
// application layer, so the initiator sends one record with an empty plaintext
// immediately after M3. It turns the responder's ratchet and confirms that both
// sides agree on the record-layer key schedule before any real message exists.
// A non-empty M4 is refused.
//
// # Record layer: Double Ratchet
//
// Initialisation follows the published algorithm:
//
//	Responder: DHs = its handshake ephemeral pair (e_r), RK = RK0,
//	           CKs = nil, CKr = nil
//	Initiator: DHr = e_r, RK = RK0, generates a FRESH ratchet pair DHs, then
//	           RK, CKs = KDF_RK(RK0, X25519(DHs, DHr))
//
// Symmetric-key (chain) ratchet, once per message:
//
//	mk  = HMAC-SHA-256(CK, 0x01)
//	CK' = HMAC-SHA-256(CK, 0x02)
//
// Diffie-Hellman ratchet, whenever a header carries a ratchet public key not
// seen before:
//
//	RK, CKr = KDF_RK(RK, X25519(DHs, DHr_new))
//	DHs     = fresh X25519 pair
//	RK, CKs = KDF_RK(RK, X25519(DHs, DHr_new))
//
//	KDF_RK(rk, dh) = HKDF(SHA-256, ikm = dh, salt = rk,
//	                      info = "CMD-CHAT-E2EE v1 ratchet root", 64) -> (rk', ck)
//
// Per-message keys, derived from mk so that key AND nonce are unique per
// message:
//
//	out     = HKDF(SHA-256, ikm = mk, salt = nil,
//	               info = "CMD-CHAT-E2EE v1 message keys", 44)
//	aeadKey = out[0:32]
//	nonce   = out[32:44]
//
// A counter is never used as a nonce, so no counter reset can cause nonce reuse.
// Every AEAD invocation in this package uses a key that is used for exactly one
// message.
//
// # Record format
//
//	header = version(1) || ratchetPub(32) || pn(uint32be) || n(uint32be)   // 41 bytes
//	ad     = AD0 || header
//	record = header || AEAD-Seal(aeadKey, nonce, ad, pad(plaintext))
//
// The header is authenticated but not encrypted. Header encryption (Signal's
// optional variant) would additionally hide the ratchet key and counters, which
// only matters against an attacker who has already broken TLS; it is recorded as
// future work in SECURITY.md rather than half-implemented here.
//
// pad() is ISO/IEC 7816-4 padding to a multiple of 256 bytes: append 0x80 then
// 0x00 until the length is a multiple of the block. This coarsens the length
// signal a network observer sees; it does not eliminate it.
//
// # Ordering, loss, duplication, replay
//
//   - n is the index within the current sending chain; pn is the length of the
//     previous sending chain. Together they let the receiver derive the message
//     keys it skipped.
//   - Skipped keys are stored under (ratchetPub, n), bounded by MaxSkip per chain
//     and MaxSkipStore in total, oldest evicted first. Out-of-window messages are
//     REJECTED, not silently accepted.
//   - A message key is DELETED the moment it successfully decrypts a message.
//     A replayed or duplicated ciphertext therefore finds no key and is rejected,
//     because the chain has already moved past it and the key cannot be
//     recomputed. This is the replay protection; it needs no separate list.
//   - A modified ciphertext, a modified header, a modified AD0 (i.e. a record
//     from a different session) and a truncated record all fail the Poly1305 tag
//     check, and the receiving state is left EXACTLY as it was — a failed
//     decryption must never advance a chain.
//
// # Post-compromise security
//
// Two mechanisms, and neither is "TLS already does that":
//
//  1. The DH ratchet. Every time the peer's ratchet public key changes, a fresh
//     X25519 secret is mixed into the root key. An attacker who stole the entire
//     session state is locked out again once it misses one such step, because it
//     does not have the new ratchet private key.
//  2. Explicit rekey prompts. The DH ratchet only turns when the OTHER side
//     sends. A one-sided conversation would otherwise chain-ratchet forever
//     without ever mixing new DH material. Session.NeedsRekey reports when this
//     side has sent RekeyAfterMessages messages or RekeyAfterInterval has passed
//     since the last DH step; the chat layer then sends an encrypted "rekey"
//     control packet, and the peer answers with "rekey_ack", which necessarily
//     carries its new ratchet public key and turns the ratchet.
//
// Forward secrecy comes from the chain ratchet (per message) and the DH ratchet
// (per step), plus the fact that the handshake used only ephemeral DH: the
// long-term Ed25519 keys sign, they never encrypt, so recovering one later
// decrypts nothing that was captured earlier.
//
// # Key hierarchy
//
//	Long-term identity key   Ed25519 sk        on disk, sealed; signs only
//	Ephemeral handshake key  X25519 e_i / e_r  RAM only, discarded after init
//	Handshake secret PRK     32 bytes          RAM only, discarded after init
//	Root key RK              32 bytes          RAM only, evolves per DH step
//	Sending chain key CKs    32 bytes          RAM only, evolves per message
//	Receiving chain key CKr  32 bytes          RAM only, evolves per message
//	Message key mk           32 bytes          RAM only, ONE message, then wiped
//	AEAD key + nonce         32 + 12 bytes     derived from mk, single use
//
// Each level is derived from the one above by a one-way function with a distinct
// label, so learning a level does not yield the level above it, and learning one
// message key yields exactly one message.
//
// # Domain separation
//
// Every KDF, signature and MAC input in this package begins with a distinct
// ASCII label that names the protocol, the version and the purpose. The labels
// are listed in one place, labels.go, and each is used for exactly one purpose.
// No key derived under one label is ever used under another.
//
// # What this package does NOT do
//
//   - It does not hide metadata. See the metadata table in SECURITY.md.
//   - It does not protect a compromised endpoint's live plaintext.
//   - It does not authenticate anything a host says ABOUT a third party. In a
//     group room each guest has a CMDC1 session with the HOST only; the host is a
//     participant and can read what it relays. That is a property of the star
//     topology, not a flaw in this package, and it is stated plainly in
//     SECURITY.md rather than papered over.
//   - It has not been independently audited.
package e2ee

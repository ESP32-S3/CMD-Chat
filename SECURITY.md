# CMD-Chat security

This document describes what CMD-Chat protects, how, and — just as importantly —
what it does not protect.

It uses precise claims. CMD-Chat is **not** "unbreakable", "100% secure" or
"state-level secure", and nothing here should be read as saying so. The code
described below **has not been independently audited**.

For the state of things before this design existed, see
[`docs/SECURITY-BASELINE.md`](docs/SECURITY-BASELINE.md).

---

## 1. Summary

CMD-Chat carries two independent layers of encryption:

| Layer | Protocol | Protects against |
|---|---|---|
| Transport | TLS 1.3 | passive observers on the network, tampering on the hop |
| Application | **CMDC2** (this document) | the relay, the phonebook, Cloudflare, an ISP, and anyone who has terminated or broken TLS |

TLS is not removed and not weakened. CMDC2 sits **above** it. Every byte the
relay moves is CMDC2 ciphertext inside a TLS record.

Message plaintext exists only in the memory of the two people's own computers.

---

## 2. Threat model

### 2.1 Attackers CMDC2 is designed to resist

| Attacker | Capability | Result |
|---|---|---|
| Passive network observer / ISP | reads all traffic | sees ciphertext and timing only |
| The relay Worker | reads, drops, delays, reorders, duplicates, injects | cannot read or forge a message; can deny service |
| The D1 phonebook | chooses what a lookup returns, including keys and fingerprints | cannot substitute a peer for one the user asked for |
| Cloudflare | operates both of the above, and terminates TLS | same as the two rows above, combined |
| An active MITM that terminates TLS on both sides | full control of both TLS sessions | **handshake fails**; see §5 |
| An attacker who later steals a long-term identity key | offline, after the fact | cannot decrypt anything captured earlier; can impersonate going forward |
| An attacker who steals one message key | | decrypts exactly one message |
| An attacker recording traffic now to decrypt with a future quantum computer | passive, patient | **cannot decrypt it**; see §5.3 and §8.4 |
| An attacker who briefly compromised an endpoint and was evicted | had full session state | loses access once one DH ratchet step passes without it |

### 2.2 Attackers CMDC2 does **not** resist

* **A compromised endpoint, while it is compromised.** Malware on your computer
  reads your screen and your keyboard. No messaging protocol changes that.
* **The other person.** They can screenshot, copy, or repeat anything you say.
* **A host in a group room.** See §9.
* **Traffic analysis.** See §10.
* **An attacker who controls the channel you exchanged IDs over.** See §6.

---

## 3. Cryptographic primitives

All are standard-library or `golang.org/x/crypto`. **No primitive is implemented
in this repository.**

| Purpose | Primitive | Source |
|---|---|---|
| Identity signatures | Ed25519 | `crypto/ed25519` |
| Key agreement (classical) | X25519 | `crypto/ecdh` |
| Key agreement (post-quantum) | ML-KEM-768, FIPS 203 | `crypto/mlkem` |
| Hashing / transcript | SHA-256 | `crypto/sha256` |
| KDF | HKDF-SHA-256 | `golang.org/x/crypto/hkdf` |
| Chain / MAC | HMAC-SHA-256 | `crypto/hmac` |
| AEAD | ChaCha20-Poly1305, 256-bit key, 96-bit nonce | `golang.org/x/crypto/chacha20poly1305` |
| Identity file sealing (passphrase) | scrypt (N=2¹⁵, r=8, p=1) + XChaCha20-Poly1305 | `golang.org/x/crypto/scrypt`, `.../chacha20poly1305` |
| Identity file sealing (Windows) | DPAPI `CryptProtectData` | the operating system |
| Randomness | `crypto/rand` | the operating system |

Dependencies: `golang.org/x/crypto`, `golang.org/x/sys`. Nothing else.

---

## 4. Construction, and why this one

The requirement is a **two-party, interactive** session. Both endpoints are
online simultaneously, because CMD-Chat has no offline delivery and no message
store.

* **X3DH was not used.** It exists so Alice can send to an offline Bob using
  prekeys held by a server. CMD-Chat has neither the offline case nor a server
  that could hold prekeys.
* **MLS was not used.** It solves continuous group key agreement for large,
  membership-changing groups. A CMD-Chat room is a star of independent two-party
  links around one human host (§9).
* **What is used:** **SIGMA-I** (signed-and-MACed authenticated ephemeral
  Diffie–Hellman) for the handshake, then the **Double Ratchet** for the record
  layer.

The ephemeral Diffie–Hellman is **hybrid**: X25519 and ML-KEM-768 run together,
exactly as TLS 1.3 does with its X25519MLKEM768 group.

SIGMA is the pattern underneath IKEv2 and, in its signed-transcript form,
underneath TLS 1.3's own authentication. It is close in shape to the Noise
`IK`/`XX` patterns, but authenticates with signatures over a transcript rather
than with static-static DH — which is what lets CMD-Chat keep its **existing**
Ed25519 identities without converting them to X25519. No key is used for two
algorithms.

The Double Ratchet is used **as published** (Perrin & Marlinspike). No new
ratchet was invented. No Signal code was copied.

---

## 5. The handshake

Roles: the guest (the side that dialled) is the **initiator**; the host is the
**responder**.

```
Initiator                                                    Responder
---------                                                    ---------
M1  type=1 | versions[] | e_i(32) | ek(1184) | rand_i(32)  ->
                                 <-  M2  type=2 | version | e_r(32) | ct(1088) | rand_r(32) | lp(C2)
M3  type=3 | lp(C3)                                        ->
M4  priming record (empty plaintext)                       ->
```

`ek` is an ML-KEM-768 encapsulation key generated fresh for this handshake; `ct`
is the ciphertext the responder produces by encapsulating against it. The ML-KEM
decapsulation key never leaves the initiator, and the secret it protects is
*created by the responder* rather than carried across the network.

### 5.1 Channel binding — the man-in-the-middle defence

The transcript **starts** from a TLS 1.3 exporter value (RFC 8446 §7.5,
RFC 5705):

```
binding = TLS-Exporter("EXPORTER-CMD-Chat-CMDC2-channel-binding", nil, 32)
```

An attacker who terminates TLS on both sides holds **two different TLS
sessions**, so the two exporter values differ. Both endpoints sign a transcript
containing their own binding, so the signatures the attacker forwards do not
verify on the far side. **The handshake fails.**

This is the property the old design lacked, and it is why a hostile relay or a
hostile phonebook cannot get between two users. There is **no unbound mode** and
no way to negotiate one: a session without a binding is refused outright.

Verified by `TestTLSTerminatingRelayCannotBecomeAManInTheMiddle`, which runs a
real TLS-terminating attacker holding both sessions and pinning its own
certificate.

### 5.2 Transcript

```
lp(x) = uint32be(len(x)) || x

th0 = SHA256( "CMD-CHAT-E2EE v1 transcript" || lp(binding) )
th1 = SHA256( th0 || lp(M1) )
th2 = SHA256( th1 || lp(M2header) )
th3 = SHA256( th2 || lp(C2) )
th4 = SHA256( th3 || lp(C3) )
```

Every variable-length field is length-prefixed, so two different transcripts can
never produce the same hash input.

### 5.3 Hybrid key agreement, and the handshake key schedule

```
ss_classical = X25519(e_i, e_r)         -- crypto/ecdh rejects an all-zero result
ss_quantum   = ML-KEM-768 Encap/Decap   -- 32 bytes
shared       = ss_quantum || ss_classical
PRK          = HKDF-Extract(SHA-256, salt = th2, ikm = shared)

k_r = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs responder key", 32)
k_i = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs initiator key", 32)
m_r = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs responder mac", 32)
m_i = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 hs initiator mac", 32)

C2 = AEAD-Seal(k_r, nonce=0^12, ad = th2, AuthPayload_responder)
C3 = AEAD-Seal(k_i, nonce=0^12, ad = th3, AuthPayload_initiator)
```

**Why both, rather than just the post-quantum one.** Concatenate-then-KDF is the
standard hybrid combiner, in the same order TLS uses, and the salt is a
transcript hash that already commits to both public values. The result is secure
if **either** component is secure:

* if ML-KEM falls to classical cryptanalysis — a genuine risk for a lattice
  scheme this young — X25519 still holds the session;
* if a quantum computer breaks X25519, ML-KEM still holds it.

Neither is trusted alone. This is strictly stronger than the X25519-only exchange
it replaces.

**Implicit rejection.** FIPS 203 specifies that decapsulating a corrupted
ciphertext yields a *pseudorandom* secret rather than an error. So a forged `ct`
does not fail at the KEM; it fails a few steps later when the AEAD tag on `C2`
does not verify. An attacker learns nothing from the shape or timing of the
failure. Only a wrong *length* is an error, and the parser fixes the length.

The all-zero nonce is safe **only** because `k_r` and `k_i` each encrypt exactly
one ciphertext in the lifetime of a session, under a key derived from a
transcript containing two fresh ephemerals and two 32-byte randoms. The record
layer does not use this pattern; it derives a fresh key **and** nonce per
message.

### 5.4 AuthPayload, signature, and key confirmation

```
identityPub[32] | lp(id) | signature[64] | mac[32] | lp(nickname)

sig_r = Ed25519-Sign(sk_r, "…responder signature" || 0x00 || th2 || pub_r || lp(id_r))
mac_r = HMAC-SHA-256(m_r, "…responder confirm"   || 0x00 || th2 || pub_r || lp(id_r))
sig_i = Ed25519-Sign(sk_i, "…initiator signature" || 0x00 || th3 || pub_i || lp(id_i))
mac_i = HMAC-SHA-256(m_i, "…initiator confirm"   || 0x00 || th3 || pub_i || lp(id_i))
```

* The **signature** binds the ephemeral keys, the channel binding and the version
  negotiation to a long-term identity.
* The **MAC** is SIGMA's key confirmation: it proves the signer is the same party
  that holds the DH secret. This is what rules out **unknown-key-share**, where a
  genuine signature is relayed to bind someone's identity to a key exchange they
  never took part in.
* The initiator signs `th3`, which covers `C2`, which covers the responder's
  identity. So both sides finish with agreement on the **full** transcript,
  including *who the other party is*. Neither can be confused about which stable
  identity it authenticated.

The verifier additionally:

1. rejects small-order and non-canonical Ed25519 public keys
   (`internal/e2ee/smallorder.go` — `crypto/ed25519` follows RFC 8032 and will
   otherwise verify an all-zero signature under the all-zero key);
2. recomputes `"cc-" || base32(SHA-256(pub)[0:10])` and requires it to equal the
   claimed ID;
3. requires the ID to equal `ExpectPeerID` when one was requested;
4. consults the trust store (§6).

Failures 1–3 all return the same opaque error, so a prober learns nothing from
which check fired.

### 5.5 Version negotiation

`M1` offers every version this build supports; `M2` names the one chosen, picked
by the **responder's** preference order among what was offered. Both the offered
list and the choice are inside the signed transcript, so stripping a version to
force a weaker one is detected. An unsupported version fails closed.

Two versions exist, and only one is implemented:

| Version | Key agreement | Status |
|---|---|---|
| **V1** | X25519 only | **refused.** Recognised only so a peer running it gets a useful message |
| **V2** | X25519 + ML-KEM-768 | the only version this build speaks |

**V1 is refused rather than supported, deliberately.** The entire point of the
post-quantum exchange is to defeat an attacker who records traffic now and
decrypts it decades later. A session that quietly fell back to V1 would hand that
attacker exactly what it wants, while both users saw a connection that looked
completely normal. So an out-of-date peer gets an error naming the problem, and
no session. There is likewise no fallback to the pre-CMDC2 handshake — that code
was deleted, not disabled.

### 5.6 Session keys

```
RK0 = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 root key"        || th4, 32)
AD0 = HKDF-Expand(PRK, "CMD-CHAT-E2EE v1 associated data" || th4, 32)
```

`AD0` is mixed into every record's associated data, so a ciphertext captured in
one session can never be replayed into another between the same two people.

### 5.7 M4, the priming record

The Double Ratchet responder has no sending chain until it sees the initiator's
first ratchet public key. CMD-Chat's host speaks first at the application layer,
so the initiator sends one record with an empty plaintext immediately after M3.
It turns the responder's ratchet and confirms both sides agree on the
record-layer key schedule before any real message exists. A non-empty M4 is
refused.

---

## 6. Authentication, and the first exchange

### 6.1 What is cryptographic

A CMD-Chat ID **is** a hash of a public key:

```
cc- || base32( SHA-256(ed25519_public_key)[0:10] )
```

So a user who typed or pasted a friend's ID has, without realising it, already
committed to that friend's exact key. The handshake will accept nothing else.

This is why the **first** exchange is safe against the network: the phonebook,
the relay and a LAN broadcast are all attacker-influenceable, so none of them is
allowed to supply the identity that gets pinned. `connect.Join` always pins **the
ID the user typed**:

* `phonebook.Lookup` rejects an answer whose `id` is not the one requested, and
  rejects a `public_key` that does not derive that ID (`ErrDirectoryMismatch`).
* `discovery.Find` drops any LAN announcement whose ID is not the one searched
  for.
* `connect.Result.HostID` is the caller's target, never `peer.ID`,
  `announcement.ID`, or the relay's `session.PeerID`.

### 6.2 What is not, and cannot be

If the **ID itself** reached the user through a channel the attacker controls —
a messaging app the attacker reads, a web page it can rewrite — then handing over
*its* ID instead of the friend's defeats everything above, because the user
really is talking to the identity they were given. No protocol can fix this
alone.

The mitigation is a **safety number**: a stable 160-bit code derived from both
long-term identity keys, identical on both screens and different for every pair.

```
SafetyNumber = base32( SHA-256( "…safety number" || 0x00 || min(pubA,pubB) || max(pubA,pubB) )[0:20] )
```

CMD-Chat prints it on connection, says clearly whether this is a **first
contact**, and `/verify` shows it again at any time. Two people who read it to
each other on a phone call have ruled out a man in the middle. This is the same
idea as Signal's safety numbers and OTR's fingerprints.

### 6.3 Key changes fail closed

The trust store (`internal/auth`) maps ID → public key, with first-seen and
last-seen timestamps. A known ID presenting a **different** key aborts the
handshake with `ErrKeyChanged`. There is:

* no prompt,
* no "accept anyway",
* no code path reachable from the network that can clear the entry.

The only way forward is the deliberate local command `cmd-chat forget <id>`,
after confirming out of band that the person really did reinstall. The next
connection is then treated as a first contact and shows a new safety number.

---

## 7. The record layer

### 7.1 Double Ratchet

```
KDF_RK(rk, dh) = HKDF(SHA-256, ikm=dh, salt=rk,
                      info="CMD-CHAT-E2EE v1 ratchet root", 64) -> (rk', ck)

mk  = HMAC-SHA-256(ck, 0x01)          -- symmetric ratchet, once per message
ck' = HMAC-SHA-256(ck, 0x02)

out     = HKDF(SHA-256, ikm=mk, info="CMD-CHAT-E2EE v1 message keys", 44)
aeadKey = out[0:32]
nonce   = out[32:44]
```

### 7.2 Nonce uniqueness

The nonce is derived **from the message key**, never from a counter. The message
key is unique per `(chain, index)` by construction, so the `(key, nonce)` pair is
unique too, and **no counter reset or state rollback can cause a nonce
collision**. Verified by `TestEveryMessageGetsAFreshKeyAndNonce`.

### 7.3 Record format

```
header = version(1) | ratchetPub(32) | pn(uint32be) | n(uint32be)   -- 41 bytes
ad     = AD0 || header
record = header || AEAD-Seal(aeadKey, nonce, ad, pad(plaintext))
```

`pad` is ISO/IEC 7816-4 padding to a multiple of **256 bytes**, so a two-character
message and a 200-character one produce identically sized records. This coarsens
the length signal; it does not remove it.

The header is authenticated but not encrypted. Header encryption (the Double
Ratchet's optional variant) would additionally hide the ratchet key and counters
from an attacker who has already broken TLS. It is **future work**, recorded here
rather than half-implemented.

### 7.4 Replay, ordering, loss

* Out-of-order messages are handled by storing skipped keys under
  `(ratchetPub, n)`, bounded by `MaxSkip = 1000` per chain and
  `MaxSkipStore = 2000` in total, oldest evicted first.
* A gap larger than `MaxSkip` is **rejected**, not accepted — otherwise a forged
  header would trigger a million key derivations on demand.
* **A message key is destroyed the moment it decrypts a message.** A replay or
  duplicate therefore finds no key, and the chain has moved past the point where
  it could be recomputed. This is the replay protection; it needs no separate
  list.
* A record that fails authentication for **any** reason leaves the session state
  exactly as it was. Decryption runs on a *clone* of the ratchet, which is
  adopted only after the Poly1305 tag verifies. So a forged, replayed or
  truncated record cannot advance a chain and cannot cause a later genuine
  message to be lost.

---

## 8. Key hierarchy and compromise boundaries

| Level | Lifetime | Location | Compromise means |
|---|---|---|---|
| Long-term Ed25519 identity | permanent | disk, sealed | future impersonation; **no** past decryption |
| Ephemeral X25519 handshake key | one handshake | RAM | that session's initial root key |
| Handshake secret `PRK` | one handshake | RAM | that session's initial root key |
| Root key `RK` | evolves per DH step | RAM | the session from that point until the next DH step |
| Sending / receiving chain key | evolves per message | RAM | that chain from that point forward |
| Message key `mk` | one message | RAM, wiped after use | **exactly one message** |
| AEAD key + nonce | one message | RAM | exactly one message |

Each level derives from the one above via a one-way function under a **distinct
label**. Learning a level never yields the level above it.

### 8.4 Reach of the post-quantum protection

The hybrid exchange happens **once**, at the start of a session. That is enough
to protect the whole conversation from an attacker who records traffic now and
hopes to decrypt it later, because of the shape of the root chain:

```
RK_next = HKDF(salt = RK_current, ikm = dh_step)
```

An attacker with a quantum computer could recover every `dh_step` — those are
X25519. It still cannot compute `RK_next`, because it never learns `RK_0`, and
`RK_0` came from the hybrid secret. The chain stays out of reach for the whole
session on the strength of the initial exchange alone.

**What is not covered.** The identity signatures are Ed25519, so a quantum
computer could forge one. That only helps an attacker operating **live**, at the
moment of a handshake; it cannot be used retroactively against a conversation
that has already happened, and the safety number (§6.2) is the backstop for a
live impersonation. Post-quantum signatures are far larger and far less settled
than ML-KEM, so the trade taken here is to secure confidentiality now and revisit
authentication when the standards mature. **This is not a fully quantum-safe
protocol; it is quantum-safe against recording.**

### 8.1 Forward secrecy

The long-term Ed25519 key **signs only**. It never encrypts and never
participates in key agreement. Session keys come from ephemeral X25519 that
existed only in RAM.

**An attacker who obtains a long-term identity key today cannot decrypt traffic
captured yesterday.** This holds against an attacker who obtains *both* parties'
identity keys.

Additionally, the chain ratchet advances once per message, so compromising the
current chain key does not decrypt earlier messages in the same chain.

### 8.2 Post-compromise security

Two explicit mechanisms — neither of which is "TLS already handles this":

1. **The DH ratchet.** Every time the peer's ratchet public key changes, a fresh
   X25519 secret is mixed into the root key. An attacker holding a complete copy
   of the session state is locked out again as soon as it misses one such step,
   because it has never seen the new ratchet private key.
2. **Explicit rekey prompts.** The DH ratchet only turns when the *other* side
   sends, so a one-sided conversation would ratchet symmetrically forever without
   new DH material. After `RekeyAfterMessages = 64` unanswered messages or
   `RekeyAfterInterval = 5 minutes`, the sender emits an encrypted `rekey`
   control packet; the peer answers with `rekey_ack`, which necessarily carries
   its new ratchet public key. A background check runs every 30 seconds, so this
   also covers an idle session.

Verified by `TestDHRatchetTurnsOnEveryReply` and
`TestNeedsRekeyFiresOnAOneSidedConversation`.

### 8.3 Domain separation

Every KDF, signature and MAC input begins with a distinct ASCII label naming the
protocol, version and purpose. All labels live in one file,
`internal/e2ee/labels.go`, so a reviewer can confirm at a glance that no two
purposes share one. **No key derived under one label is ever used under
another.**

---

## 9. Group rooms: what is and is not end-to-end

A room is **N independent two-party CMDC2 sessions around one host**. It is not
group E2EE, and this document will not call it that.

* Guest ↔ host is genuinely end to end.
* Guest ↔ guest is **not**: the host decrypts a message and re-encrypts it to
  each recipient.

This is a property of the star topology, and the host is a *person in the
conversation*, not a server. But it means:

* **The host can read everything said in a room it hosts.**
* A guest authenticates the **host** and nobody else.
* The roster, and the `From` label on other guests' messages, are the host's
  account of the room. A guest can check that each listed ID is well-formed; it
  cannot check that the list is honest or complete.
* The host does re-stamp `From` from the connection that actually authenticated,
  so one guest cannot impersonate another **to the host's own relaying**.

If you need a conversation the host cannot read, do not have it in that host's
room.

### 9.1 Nicknames

A nickname is self-asserted. It is authenticated in the sense that the peer
really sent it and nobody altered it in flight — it is inside the AEAD and inside
the transcript. It still proves **nothing** about who the peer is. Only the ID is
proven.

---

## 10. Metadata — what each party can see

End-to-end encryption does not hide metadata. It is not claimed to.

### 10.1 The D1 phonebook can see

* your CMD-Chat ID and your Ed25519 **public** key
* your current TLS certificate fingerprint
* your IP address candidates: LAN addresses, public IPv4/IPv6, STUN-discovered
  endpoints, and the source IP of your HTTPS requests
* when you come online, and roughly how long you stay (heartbeats)
* **which IDs you look up**, and when — this reveals your social graph
* your client's protocol version

It **cannot** see message content, nicknames, or any session key.

### 10.2 The relay can see

* the CMD-Chat ID of the host whose session is being joined (it is the session
  name) and the ID of the guest (both are proven by signature to the relay)
* the two IP addresses
* connection times and duration
* the **size and timing** of every frame
* nothing else. Frames are opaque ciphertext. No message ever touches disk.

It **can** drop, delay, reorder or duplicate traffic — that is denial of service,
and CMDC2 rejects the reordered/duplicated results rather than being confused by
them. It **cannot** read or forge a message, and it cannot become a man in the
middle.

### 10.3 An ISP or network observer can see

* that you connected to the Cloudflare Workers domains
* the IP address of your peer on a direct or LAN connection
* packet sizes and timing
* nothing about content

### 10.4 The peer can see

* everything you send them, obviously
* your IP address on a direct or LAN connection (not on a relayed one)
* your nickname and your ID

### 10.5 A compromised endpoint can see

* every message in that conversation, sent and received, while compromised
* the long-term identity key (subject to §11)
* the live session state — but see §8.2 for why that stops working after
  eviction

### 10.6 What is minimised

* Message lengths are padded to 256-byte blocks.
* Nicknames are never published to the phonebook — they travel only inside an
  established session.
* Log addresses are summarised ("IPv4, private") rather than printed.
* **No message content is ever logged**, at any log level.

---

## 11. Private keys at rest

| Platform | Default | Mechanism |
|---|---|---|
| Windows | DPAPI | `CryptProtectData` with an application entropy value; bound to this Windows account on this machine |
| Any platform, with `CMD_CHAT_IDENTITY_PASSPHRASE` set | passphrase | scrypt (N=2¹⁵, r=8, p=1, 32-byte salt) + XChaCha20-Poly1305 |
| macOS / Linux, no passphrase | **file permissions only** | `0600` file in a `0700` directory |

`cmd-chat security` reports which mode is in use.

**Honest limits:**

* DPAPI defends against an attacker who gets the **file** — a stolen disk, a
  backup, a sync folder, another account on the machine. It does **not** defend
  against malware running as you, which can call `CryptUnprotectData` itself.
* The passphrase mode is the only one that survives an attacker with full
  user-level access, because the secret is not stored on the machine. It is
  opt-in because CMD-Chat has never had a password prompt and adding a mandatory
  one would lock people out of their own identity.
* macOS Keychain and the freedesktop Secret Service both require cgo or a live
  session D-Bus, neither of which a statically built terminal binary can rely on.
  Rather than ship something that appears to protect the key and silently does
  not, that case is explicit and documented as the weakest.

Writes are **atomic** (temp file + rename), so a crash cannot leave a truncated
identity that would be discarded — silently changing your ID and breaking every
peer that had pinned it.

### 11.1 Zeroing memory

`e2ee.Wipe` overwrites key buffers after use, with `runtime.KeepAlive` to stop
the compiler eliding the stores. Applied to message keys after use, chain keys as
they ratchet, the handshake secret once the session starts, and plaintext buffers
after they are sealed.

**This is a real but limited measure, and Go bounds it:**

* the garbage collector may have copied a buffer during a stack growth or a slice
  append; those copies are unreachable and are not overwritten;
* nothing here touches swap, hibernation files, core dumps, or a debugger
  attached to the live process.

It shortens the window in which key material sits in reachable heap memory. It
does **not** make keys unrecoverable from a compromised machine.

---

## 12. Known limitations

1. **Not independently audited.** No third party has reviewed this.
2. **80-bit truncated-hash IDs.** `SHA-256(pub)[0:10]` gives ~80-bit resistance to
   matching a *specific* ID and ~40-bit resistance to finding *any* colliding
   pair. The second number is weak. Changing it would invalidate every ID people
   have already shared, so it stands, and safety numbers (§6.2) use the full key.
3. **Group rooms are not group E2EE.** See §9.
4. **Metadata is not hidden.** See §10.
5. **Headers are not encrypted.** See §7.3.
6. **No at-rest protection on macOS/Linux without a passphrase.** See §11.
7. **Post-quantum confidentiality only, not post-quantum authentication.** Key
   agreement is hybrid X25519 + ML-KEM-768, so recorded traffic is safe from a
   future quantum computer. The Ed25519 signatures are not, so a quantum
   adversary operating live at handshake time could impersonate someone. See
   §8.4.
8. **The relay can deny service.** It cannot read anything, but it can stop the
   conversation.
9. **Endpoint compromise is out of scope**, as it is for every messenger.

---

## 13. Reporting a vulnerability

Open an issue at <https://github.com/ESP32-S3/CMD-Chat/issues>. For anything you
believe is exploitable, please say so in the issue title and avoid posting a
working exploit until it has been looked at.

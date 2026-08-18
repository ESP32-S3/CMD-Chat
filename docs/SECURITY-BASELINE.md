# CMD-Chat security baseline (pre-E2EE)

This document records the security properties of CMD-Chat **as it existed
before** the application-layer end-to-end encryption work, so that the changes
that followed can be judged against a written starting point. It describes
commit `7e286f0` on branch `feat/group-chat`.

It is kept as an audit record. For the current design, see
[`SECURITY.md`](../SECURITY.md).

---

## 1. What the code actually did

### 1.1 Identity

`internal/identity`

* Ed25519 keypair generated with `crypto/rand`, stored as **plaintext JSON** at
  `$UserConfigDir/cmd-chat/identity.json` with mode `0600`.
* Stable ID: `"cc-" + base32(sha256(pub)[0:10])` — an 80-bit truncated hash.
* `LoadOrCreate` validates that the stored private key really derives the stored
  public key and that the ID matches, and silently regenerates otherwise.

### 1.2 Transport

`internal/chat`

* Host generates a **fresh, self-signed RSA-2048 certificate on every process
  start** (`newTLSConfig`) and serves `tls.Listen` with `MinVersion: TLS 1.3`.
* Guest dials with `InsecureSkipVerify: true` and pins the certificate by
  SHA-256 fingerprint, where the fingerprint came from LAN discovery or from the
  Cloudflare D1 phonebook.
* If the expected fingerprint is empty, the guest prints a warning and
  **continues anyway**.

### 1.3 Peer authentication

`internal/auth`

* Mutual Ed25519 challenge/response *inside* the TLS session:
  * each side sends a 32-byte random nonce;
  * the other side returns
    `Ed25519_Sign(sk, "CMD-CHAT/1\x00" || ID || "\x00" || nonce)` together with
    its public key;
  * the verifier recomputes `"cc-" + base32(sha256(pub)[0:10])` and requires it
    to equal the claimed ID, then verifies the signature.
* Trust-on-first-use store (`internal/auth/trust.go`) maps ID → public key and
  **refuses the connection if a known ID presents a different key**.

### 1.4 Message framing

* `json.Encoder` / `json.Decoder` streams of `chat.Packet`
  (`{type, from, name, text, members, group}`) directly over the TLS conn.
* 4096-byte cap on `text`, enforced on send and on the host's receive path.
* Host re-stamps `From`/`Name` from the authenticated connection before
  rebroadcasting, so a guest cannot impersonate another guest.

### 1.5 Relay and phonebook

* `workers/relay` — Cloudflare Durable Object; forwards **binary** WebSocket
  frames between exactly two authenticated sockets and holds nothing on disk.
  Session name = host's CMD-Chat ID; role/session/ID/timestamp is signed with
  the Ed25519 identity key, so only the ID owner can claim the host slot.
* `workers/phonebook` — Cloudflare Worker + D1. Stores `cmd_chat_id`,
  `public_key`, `session_fingerprint`, `protocol_version`, address candidates
  and timestamps. Registration is signed by the identity key and the Worker
  checks that the public key derives the claimed ID.

---

## 2. Properties that genuinely held

| Property | Held? | Basis |
|---|---|---|
| Confidentiality against a *passive* network observer | Yes | TLS 1.3 between the two clients |
| Confidentiality against the relay Worker | Yes, in practice | Relay forwarded opaque TLS records and never held a TLS key |
| Message integrity on the wire | Yes | TLS 1.3 AEAD |
| Proof the peer holds the private key for its claimed ID | Yes | Ed25519 challenge/response with a fresh nonce per connection |
| Rejection of an identity key change for a known ID | Yes | `auth.Store.Trust` errors and the connection is dropped |
| Guest-to-guest impersonation inside a room | Prevented | Host re-stamps `From` |
| Forward secrecy of the *transport* | Yes, per TLS session | TLS 1.3 is ECDHE-only |
| Replay of a whole *session* | Prevented | Fresh nonces per connection |

---

## 3. Weaknesses found

Ordered by severity.

### W1 — CRITICAL: the identity handshake was not bound to the TLS channel

The Ed25519 challenge/response signed only `"CMD-CHAT/1" || ID || nonce`. It
said nothing about *which* TLS session it was running inside.

An attacker able to terminate TLS on both sides — exactly the position of a
hostile relay, a hostile phonebook, or Cloudflare — could:

1. publish (or substitute) its own certificate fingerprint in D1, so the guest
   pins the *attacker's* certificate and `InsecureSkipVerify: true` accepts it;
2. open a second TLS session to the real host;
3. forward each challenge and each response verbatim between the two sessions.

Both endpoints would then report a successful mutual authentication, print
`Authenticated host …`, and hand every subsequent plaintext `Packet` to the
attacker. This is an authentication-relay / man-in-the-middle break, and it
defeated the claim in `internal/relay/relay.go` that "a hostile relay … cannot
become a man in the middle".

The pinned fingerprint was the only thing standing between the users and this
attack, and that fingerprint was delivered by the same party being defended
against.

### W2 — CRITICAL: no application-layer encryption at all

Confidentiality rested entirely on the single TLS hop. The stated requirement is
that the relay, D1, Cloudflare and a TLS MITM never see plaintext. With W1 a TLS
MITM saw everything, and there was no second layer to fall back on.

### W3 — HIGH: unpinned connections were accepted with a printed warning

`chat.ClientConn` with an empty `expectedFingerprint` printed
`Warning: host certificate is not pinned` and continued. Combined with W1 that is
an unauthenticated channel. `cmd-chat join --address host:port` with no
`--fingerprint` took this path by default.

### W4 — HIGH: plaintext message contents were written to the debug log

`cmd/cmd-chat/main.go` logged `debug.Log("Host message sent: %q", text)` on both
the `ready`/`hostChat` path and the `host` subcommand. With `/debug` enabled,
every outgoing message was written in cleartext to
`$UserConfigDir/CMD-Chat/logs/crash-*.log` — a `0644` file in a `0755`
directory.

### W5 — HIGH: no forward secrecy at the application layer, and none across reconnects

With TLS as the only protection, forward secrecy is whatever TLS gives: per
connection, and gone the moment an endpoint's TLS session keys are recovered
from memory. There was no independent ephemeral key exchange, no root key and no
ratchet, so there were no per-message keys, no key separation of any kind, and
no mechanism for post-compromise recovery.

### W6 — MEDIUM: no post-compromise security

Nothing rekeyed during a session. A single compromise of the live session state
compromised the rest of the conversation indefinitely.

### W7 — MEDIUM: long-term private key stored in cleartext on disk

`identity.json` held the raw Ed25519 key in base64 JSON, protected only by
filesystem permissions. Any process running as the user, any backup, any sync
client and any offline disk read recovered it.

### W8 — MEDIUM: no application-layer replay or ordering protection

There was no sequence number, no counter and no anti-replay window in the
`Packet` format. TLS provided this *within* one session only; nothing carried
across a reconnect.

### W9 — MEDIUM: no protocol version negotiation in the peer handshake

`"CMD-CHAT/1"` was a hard-coded string inside the signed payload. There was no
version list, no negotiation, and so no way to detect a downgrade or to
introduce a v2 that fails closed against a v1 attacker.

### W10 — LOW/MEDIUM: 80-bit truncated-hash identity

`sha256(pub)[0:10]` gives roughly 80-bit second-preimage strength for targeting a
*specific* ID and roughly 40-bit collision strength for producing *any*
colliding pair. 40 bits is within reach of a determined attacker who only needs
some collision. Changing it is a breaking change to every published ID.

### W11 — LOW: no domain separation discipline

Three signing contexts existed (`CMD-CHAT/1`, `cmd-chat-relay/v1`,
`cmd-chat-phonebook/v1`) and were correctly distinct, but there was no KDF
anywhere, so the property had simply not been established rather than violated.

### W12 — LOW: nickname is unauthenticated by design, and the roster is the host's word

Documented behaviour, not a defect: `Response.Name` sits outside the signed
payload, and in a group room the roster and the `From` label on other guests'
messages are asserted by the host. A guest authenticates the host and nobody
else. This remains true and is restated in `SECURITY.md`.

### W13 — LOW: no length hiding

`chat.Packet` was JSON-encoded straight into TLS, so record lengths tracked
message lengths closely.

---

## 4. Summary judgement

Before this work CMD-Chat was **transport-encrypted, not end-to-end
encrypted**. Its authentication was sound against a passive attacker and against
a relay that only moved bytes, but it was structurally broken against an active
attacker in the position the phonebook and relay actually occupy (W1), and it
had none of: forward secrecy beyond the TLS session, post-compromise security,
per-message key separation, application-layer replay protection, or at-rest key
protection.

The redesign that follows targets exactly those gaps.

# cmd-chat-phonebook

A Cloudflare Worker + D1 database that acts as the **public phonebook / rendezvous directory** for
[CMD-Chat](../../README.md), a peer-to-peer terminal chat application.

## What this is (and is not)

```
CMD-Chat client
    |
    v
Cloudflare Worker HTTPS API      <-- this repo
    |
    v
D1 phonebook                     <-- discovery data only
    |
    v
connection / discovery information
    |
    v
NAT traversal between CMD-Chat clients
    |
    v
direct encrypted peer-to-peer chat
```

**D1 is not the chat server.** No message, no key exchange, and no session state ever transits this
Worker. It answers exactly one question — *"where might I reach `cc-XXXX` right now?"* — and then
gets out of the way. The two clients connect directly to each other.

The four stages are deliberately kept distinct:

| Stage                  | Who does it            | Guaranteed?                                        |
| ---------------------- | ---------------------- | -------------------------------------------------- |
| 1. Discovery           | this Worker + D1       | Yes, when the peer is registered and not stale      |
| 2. NAT traversal       | the two clients        | **No** — fails on symmetric / CGNAT / strict firewalls |
| 3. Direct P2P transport| the two clients        | Only if (2) succeeded                               |
| 4. Relay fallback      | *does not exist*       | Not implemented, and not planned here               |

There is no relay. If NAT traversal fails, the connection fails. The API refuses `relay` candidates
outright rather than implying a fallback that isn't there.

## Identity

CMD-Chat clients already hold an Ed25519 keypair, and the user-visible ID is derived from it:

```
cmd_chat_id = "cc-" + base32( sha256( ed25519_public_key )[0..9] )
```

(RFC 4648 base32, uppercase, unpadded — 10 bytes → 16 characters.)

Because the ID *is* a commitment to the public key, the phonebook needs no accounts, passwords,
API keys or session tokens. Ownership of an entry is proven by signing the request with the matching
private key. The private key never leaves the client.

## Data model

Two tables, split on purpose.

**`registrations`** — the stable identity half. Contains **no network addresses at all**: ID, public
key, per-session fingerprint, protocol/client version, timestamps, and replay bookkeeping.

**`candidates`** — the ephemeral connectivity half. ICE-style NAT-traversal candidates
(`host`, `server_reflexive`, `server_reflexive_http`). These are the only addresses stored, they are
replaced wholesale on every `/register`, and they are destroyed the moment an entry is revoked or
expires. An address is never a key and never identifies a user.

**`rate_limits`** — coarse fixed-window abuse counters, keyed by operation plus either a CMD-Chat ID
or a **salted hash** of the caller IP. Raw IPs are never written.

Registrations live for **300 seconds** past the last heartbeat. Stale entries are reported as
offline immediately (`expires_at` is checked on read) and physically deleted by a cron sweep, so a
registration cannot linger indefinitely.

## API

Base URL: `https://cmd-chat-phonebook.cmd-chat.workers.dev`

| Method   | Path                | Auth      | Purpose                                        |
| -------- | ------------------- | --------- | ---------------------------------------------- |
| `GET`    | `/health`           | none      | Service metadata and TTL                       |
| `GET`    | `/stun`             | none      | Echoes the public IP this Worker observed       |
| `POST`   | `/register`         | signature | Publish identity + candidates (upsert)          |
| `GET`    | `/lookup/:id`       | none      | Resolve a peer to connection information        |
| `POST`   | `/heartbeat`        | signature | Extend the TTL; liveness only                   |
| `DELETE` | `/register/:id`     | signature | Revoke the registration and destroy addresses   |

Every response is JSON. Failures carry a stable machine-readable `error` code
(`invalid_id`, `invalid_signature`, `id_key_mismatch`, `replayed_request`, `rate_limited`,
`offline`, `not_found`, …) that clients switch on.

### `/stun` and the port problem

The Worker can see the source **IP** of your HTTPS connection, and reports it. It deliberately
reports `port_observable: false`: the TCP source port of an HTTPS request is not the UDP port your
hole-punching socket will use, so publishing it would be actively misleading. Clients that need a
true server-reflexive `IP:port` pair must obtain it from a real STUN server and submit it as a
`server_reflexive` candidate.

### Request signing

Mutating endpoints require an `X-CmdChat-Signature` header: base64 of an Ed25519 signature over

```
cmd-chat-phonebook/v1\n
<METHOD>\n
<path>\n
<issued_at_ms>\n
<sha256_hex_of_raw_request_body>
```

The body must contain `id`, `public_key` and `issued_at`. The Worker then checks that

1. `sha256(public_key)` derives the claimed `id` — you cannot speak for an ID you don't hold,
2. the signature verifies — the body cannot be tampered with in flight,
3. `issued_at` is within ±120 s of server time, and
4. `issued_at` is **strictly greater** than the last accepted request for that ID — replay is dead.

Because of (4), a client must never reuse a timestamp; use `max(now_ms, last + 1)`.

### Example

```bash
node scripts/phonebook.mjs identity --out alice.json
node scripts/phonebook.mjs register  --identity alice.json --url https://cmd-chat-phonebook.cmd-chat.workers.dev
node scripts/phonebook.mjs lookup    cc-XXXXXXXXXXXXXXXX --url https://cmd-chat-phonebook.cmd-chat.workers.dev
node scripts/phonebook.mjs heartbeat --identity alice.json --url https://cmd-chat-phonebook.cmd-chat.workers.dev
node scripts/phonebook.mjs delete    --identity alice.json --url https://cmd-chat-phonebook.cmd-chat.workers.dev
```

`scripts/phonebook.mjs` is the executable reference implementation of the client side of this
protocol, and is what the Go client is ported from.

## What is deliberately not stored

- chat messages of any kind
- private keys, seeds, passwords, passphrases or tokens (these are **rejected** with
  `secret_material_rejected` if a client ever sends them)
- raw IP addresses as identity, or in the rate-limit table
- any user profile information — there is no display name, email or free-text field

## Development

```bash
npm install
cp .dev.vars.example .dev.vars          # put any random value in IP_HASH_SALT

npx wrangler d1 migrations apply cmd-chat-phonebook --local
npx wrangler dev
npm test                                 # vitest, runs against the real migrations
```

Deploying:

```bash
npx wrangler secret put IP_HASH_SALT     # production salt; never commit this
npx wrangler d1 migrations apply cmd-chat-phonebook --remote
npx wrangler deploy
```

Schema changes go in `migrations/` as a new numbered file — never by running ad-hoc SQL against
production.

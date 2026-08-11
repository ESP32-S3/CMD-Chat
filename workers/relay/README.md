# cmd-chat-relay

A Cloudflare Worker + Durable Object that acts as the **encrypted fallback transport** for
[CMD-Chat](../../README.md), for peers that cannot reach each other directly.

## What this is

```
CMD-Chat A                                CMD-Chat B
     |                                          |
     |  1. find each other via the phonebook    |
     |------------------------------------------|
     |                                          |
     |  2. try direct: LAN, IPv6, IPv4          |
     |<---------------- direct ---------------->|
     |                                          |
     |  3. only if that fails:                  |
     +------------> [ this relay ] <------------+
                     forwards bytes
                     it cannot read
```

The relay pairs exactly two authenticated peers on one session and forwards binary WebSocket frames
between them, unchanged and unexamined. That is the whole job.

## What it is not

**It is not a chat server, and it is not a trusted party.** The peers' TLS 1.3 session is established
end to end *inside* this pipe, and the guest pins the host's certificate fingerprint (published in
the phonebook) exactly as it would on a LAN. The relay therefore:

- holds none of the keys needed to read a message
- cannot forge or modify traffic without breaking the peers' TLS session
- cannot impersonate a peer, because identity is proven end to end

A hostile or compromised relay can drop or delay bytes — denial of service, not disclosure.

**It stores nothing.** This Worker has no D1, KV or R2 binding of any kind. That separation is
structural: it is impossible for chat bytes to reach the phonebook database, and a relay deploy can
never break peer discovery.

## Authentication

Joining reuses the identity CMD-Chat already has, rather than inventing a second one. A CMD-Chat ID
is `'cc-' + base32(sha256(ed25519_public_key)[0..9])`, so an ID is a commitment to its public key.

A join request carries these headers:

| Header                  | Meaning                                    |
| ----------------------- | ------------------------------------------ |
| `X-CmdChat-Role`        | `host` or `guest`                          |
| `X-CmdChat-Id`          | the caller's CMD-Chat ID                   |
| `X-CmdChat-PublicKey`   | base64 Ed25519 public key                  |
| `X-CmdChat-IssuedAt`    | unix milliseconds                          |
| `X-CmdChat-Signature`   | base64 Ed25519 signature (see below)       |

The signed string is newline-joined, with role and session bound in so a captured signature cannot
be replayed into a different session or used to claim the host slot:

```
cmd-chat-relay/v1
<role>
<session>
<id>
<issued_at_ms>
```

The Durable Object then checks that the public key derives the claimed ID, that the signature
verifies, that `issued_at` is within ±120 s, and — for `role=host` — that the caller **owns** the
session, since a session is named after its host's ID.

## Abuse limits

The relay is not an open proxy: you need a real CMD-Chat identity, and a guest can only connect to a
host that is actively waiting. On top of that:

| Limit                    | Value       |
| ------------------------ | ----------- |
| Session duration         | 30 minutes  |
| Idle host with no guest  | 10 minutes  |
| Bytes per session        | 32 MiB      |
| Single frame             | 64 KiB      |
| Concurrent chats per host| 4           |

## Session model

A host parks one **standby** socket and waits. When a guest arrives, the standby socket is *promoted*
into a pair and the standby slot is freed, so the host can immediately park a fresh socket for the
next guest without disturbing the live conversation. Text frames are relay control messages
(`waiting`, `paired`, `peer_left`, `ping`/`pong`) and are never forwarded; only binary frames cross
between peers.

## API

Base URL: `https://cmd-chat-relay.cmd-chat.workers.dev`

| Method | Path             | Purpose                                        |
| ------ | ---------------- | ---------------------------------------------- |
| `GET`  | `/health`        | Service metadata and limits                    |
| `GET`  | `/relay/:id`     | WebSocket upgrade; `:id` is the host's CMD-Chat ID |

Refusals come back as JSON with a stable `error` code: `no_host`, `session_busy`, `invalid_signature`,
`id_key_mismatch`, `not_session_owner`, `clock_skew`, `invalid_role`, `invalid_session`.

## Development

```bash
npm install
npx wrangler dev        # local, with a local Durable Object
npm test                # vitest, exercises auth, pairing and forwarding
npx wrangler deploy
```

### A note for anyone changing the forwarding path

Two non-obvious things are load-bearing, and both have regression tests:

1. **`server.binaryType = 'arraybuffer'`** — without it a real network client's binary frames arrive
   as `Blob`s, whose `byteLength` is `undefined` and which `send()` rejects. The symptom is nasty:
   the handshake succeeds, control frames flow, and then every relayed byte is silently dropped while
   both sockets stay open. It also keeps forwarding synchronous — awaiting `blob.arrayBuffer()`
   inside the message handler could reorder frames and corrupt the TLS stream.

2. **The Worker forwards the original `Request` to the Durable Object.** Re-wrapping it, even just to
   attach a header, severs the WebSocket from the real client socket. Authentication therefore
   happens inside the Durable Object, which is only reachable through this Worker anyway.

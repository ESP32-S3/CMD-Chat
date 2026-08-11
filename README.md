# CMD-Chat

**A serverless chat tool for talking directly to another computer.**

> **Normal user? Don't download the source code. Download the latest release, extract it, and double-click the included launcher. On Windows, use `Start CMD-Chat.bat`.**
>
> **Start here: [`docs/QUICKSTART.md`](docs/QUICKSTART.md)**

CMD-Chat is built around a simple idea: **you should be able to open a chat with another person without signing up for an account, running a permanent chat server, or handing your messages to a central service.**

When someone hosts a chat, **their own computer temporarily becomes the chat server**. When the chat closes, that host server is gone.

The application interface is intentionally **terminal-based**. The release launchers only make starting that terminal application easy; they do not replace it with a graphical UI.

## The idea

```text
             CMD-Chat

      "I want to talk to Alex"
                 |
                 v
          Alex's persistent ID
                 |
                 v
        Find / reach Alex's PC
                 |
                 v
       Direct encrypted connection
                 |
                 v
             Chat

       No permanent chat server.
       No central message database.
       No account required.
```

The person who opens the chat is the temporary host. Their computer handles the chat while it is running, and the other person connects directly to it whenever the network allows.

## Why "serverless"?

CMD-Chat does not mean that **no computer ever acts as a server**. The host's computer is the temporary server.

It means there is no permanent CMD-Chat backend sitting in the middle of every conversation.

There *is* one small always-on service — the [phonebook](#the-phonebook-finding-peers-across-networks) — but it is a directory, not a conduit. It helps two peers find each other and then plays no part in the conversation. Chat traffic never passes through it, and on a LAN it is not used at all.

There is no central service required for the core chat model to:

- create accounts
- store your conversations
- keep a permanent room alive
- route every message through a company-owned server
- assign you a cloud-hosted chat identity

Instead:

```text
Traditional chat

You -> Company server -> Friend

CMD-Chat

You <---------------> Friend
          P2P

or, when you are the host:

Friend -----------> Your computer
                    temporary host
```

## What using it feels like

### Host

Open CMD-Chat and host a chat:

```text
$ cmd-chat host

Your ID: cc-K7F4A92D3B1E

Hosting chat...
Waiting for someone to connect.
```

Give the other person your persistent ID.

### Join

They open CMD-Chat and enter your ID:

```text
$ cmd-chat join cc-K7F4A92D3B1E

Searching for host...
Connected.

> yo
```

You see:

```text
[friend] yo
> 
```

The exact connection path can vary depending on the network. On the same Wi-Fi it can be a direct LAN connection. Across the Internet it may require a directly reachable host, NAT traversal, or an optional relay.

## Your ID stays the same

Your CMD-Chat ID is **not your IP address**.

Every installation has a persistent Ed25519 identity. Its public key determines the ID, so changing Wi-Fi networks, moving locations, or getting a new IP address does not change who you are.

```text
Your computer
     |
     +-- persistent identity
     |      cc-K7F4A92D3B1E
     |
     +-- current network
            192.168.1.42
            or
            142.xxx.xxx.xxx

The network address can change.
The identity does not.
```

## Same network vs. different networks

### Same Wi-Fi

This is the easiest case.

```text
Computer A
    |
    | local network
    |
Computer B
```

CMD-Chat can use LAN discovery to find the host's current local address. The chat itself then uses the direct connection.

### Different Wi-Fi networks

CMD-Chat tries to establish a direct connection when the networks allow it:

```text
Computer A
     |
     | Internet
     |
Computer B (temporary host)
```

Across the Internet the two computers first have to *find* each other, because neither knows the other's current address. That is what the phonebook does (see below).

NAT and firewall rules can still prevent a direct connection even once the peers have found each other. CMD-Chat includes networking support for detecting/probing some of these situations, but **no client can guarantee a direct connection through every firewall and NAT configuration**.

**There is currently no relay.** `internal/network/relay.go` defines a `Relay` interface as a future extension point, but nothing implements it, and CMD-Chat ships no relay server. If NAT traversal fails, the connection fails.

## The phonebook (finding peers across networks)

On a LAN, CMD-Chat finds a host by UDP broadcast. That does not work across the Internet, so there is a small public **phonebook**: a Cloudflare Worker backed by a Cloudflare D1 database.

```text
CMD-Chat client
     |
     v
Cloudflare Worker HTTPS API
     |
     v
D1 phonebook            <-- addresses only, never messages
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

**The phonebook is a directory, not a chat server.** It answers one question — *"where might I reach `cc-XXXX` right now?"* — and then gets out of the way. Your messages never touch it.

What it does and does not hold:

| Stored                                              | Never stored                          |
| --------------------------------------------------- | ------------------------------------- |
| Your CMD-Chat ID and public key                      | Chat messages of any kind             |
| This session's TLS certificate fingerprint           | Private keys, seeds, passwords, tokens |
| A short-lived list of address candidates             | Raw IP addresses as your identity      |
| Timestamps used for expiry                           | Display names, email, any profile data |

Key properties:

- **Your ID is stable; your listing is not.** The ID is derived from your public key and never changes. The listing is a temporary registration that expires **five minutes** after your last heartbeat, and the addresses in it are destroyed when it lapses or when you stop hosting.
- **Only you can change your own entry.** Every write is signed with your Ed25519 identity key, and your ID is a hash of the matching public key, so nobody can register, refresh, or delete a listing they don't hold the key for. The private key never leaves your device.
- **Direct peer-to-peer is still the transport.** The phonebook only supplies the address to dial and the TLS fingerprint to pin. The chat connection itself is the same direct, pinned, mutually-authenticated TLS 1.3 session used on a LAN.
- **Discovery is not reachability.** Finding a peer in the phonebook does not mean you can connect to them. On restrictive networks — symmetric NAT, CGNAT, strict corporate firewalls — the direct connection will still fail, and there is no relay to fall back to.

Hosting publishes your listing automatically. To stay LAN-only:

```text
cmd-chat host --publish=false
```

The directory URL is configurable in one place (`internal/phonebook`), and can be overridden with the `CMD_CHAT_PHONEBOOK_URL` environment variable if you self-host the Worker.

## Security

Serverless does not mean "unsecured."

CMD-Chat uses:

- **TLS 1.3** for encrypted transport.
- **Ed25519 identities** so a peer can prove ownership of its persistent ID.
- **Nonce-based authentication** to prevent simply claiming someone else's ID.
- **Local peer-key pinning** so an already-trusted ID cannot silently switch to a different key.
- Optional **TLS certificate fingerprint pinning** for an additional verification layer.

- **Signed phonebook writes** so a listing can only be created, refreshed or removed by the holder of the matching private key.

The private identity key remains on the device, including when publishing to the phonebook — only the public key and a signature are ever sent.

This project is a security-oriented prototype and has not undergone a formal security audit.

## Cross-platform

The core is written in Go and is intended to run on:

- Windows (CMD / PowerShell)
- Linux terminals
- macOS Terminal
- Linux environments on supported ChromeOS devices
- amd64 and arm64 systems

A lightweight Python/Tkinter ChromeOS frontend is also included for the ChromeOS client architecture.

## Build

Install Go 1.23+:

```bash
go test ./...
go build ./cmd/cmd-chat
```

Or use the bootstrap script:

```bash
python3 scripts/install.py
```

## Basic usage

Get your permanent ID:

```text
cmd-chat id
```

Host a temporary chat:

```text
cmd-chat host
```

Host without publishing to the public phonebook (LAN only):

```text
cmd-chat host --publish=false
```

Join a host. CMD-Chat searches your LAN first, then falls back to the phonebook:

```text
cmd-chat join cc-XXXXXXXXXXXXXXXX
```

Join a directly reachable host by address:

```text
cmd-chat join --address HOST:38556 --fingerprint SHA256_CERT_FINGERPRINT
```

Leave a chat with:

```text
/quit
```

## Project structure

```text
cmd/cmd-chat/        the terminal application
clients/chromeos/    ChromeOS terminal-style frontend
internal/chat/       chat connections and message protocol
internal/auth/       peer authentication and trust
internal/identity/   persistent device identity
internal/discovery/  LAN host discovery
internal/phonebook/  public rendezvous directory client (Cloudflare Worker + D1)
internal/network/    connectivity and NAT-related networking
internal/ipc/        local ChromeOS-to-Go bridge
launchers/           easy-start scripts for release packages
scripts/             setup/build helpers
docs/                user documentation
.github/workflows/   cross-platform CI and release builds
```

## What this project is

CMD-Chat is **not trying to be another Discord, Slack, or hosted messaging platform.**

It is a small tool for one specific idea:

> **If two computers want to chat, let one of those computers host the conversation.**

The rest of the project exists to make that idea reliable, portable, and secure.

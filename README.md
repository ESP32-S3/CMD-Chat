# CMD-Chat

**A serverless chat tool for talking directly to another computer.**

CMD-Chat is built around a simple idea: **you should be able to open a chat with another person without signing up for an account, running a permanent chat server, or handing your messages to a central service.**

When someone hosts a chat, **their own computer temporarily becomes the chat server**. When the chat closes, that host server is gone.

The networking underneath it exists to make that simple idea work. You do not need to care about TLS, NAT probing, peer authentication, or discovery just to send a message.

## Quick Start (No Tech Stuff)

Just want to chat? Here's the short version.

### 1. Get CMD-Chat

Download the project and make sure **Go 1.23 or newer** is installed. Then run the installer:

```bash
python3 scripts/install.py
```

On Windows, if `python3` does not work, try:

```bat
python scripts/install.py
```

The installer builds CMD-Chat for your computer and puts it in the `bin` folder.

### 2. Start a chat

One person runs:

```text
cmd-chat host
```

You'll get an ID that looks like:

```text
cc-K7F4A92D3B1E
```

**Send that ID to your friend.**

### 3. Join the chat

Your friend runs:

```text
cmd-chat join cc-K7F4A92D3B1E
```

That's it. Once connected, type a message and press Enter.

To leave, type:

```text
/quit
```

**Important:** Both people need CMD-Chat running while they chat. The host's computer is the temporary chat server, so closing it ends that chat.

> **Having trouble connecting?** Same-Wi-Fi connections are the easiest. Connections between different networks can depend on firewalls and NAT settings.

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

NAT and firewall rules can prevent a direct connection. CMD-Chat includes networking support for detecting/probing some of these situations, but **no client can guarantee a direct connection through every firewall and NAT configuration without some infrastructure to help the peers meet**.

An optional relay can be used as a fallback in deployments that provide one. The relay would forward encrypted traffic; it would not become the chat server or hold your conversations.

## Security

Serverless does not mean "unsecured."

CMD-Chat uses:

- **TLS 1.3** for encrypted transport.
- **Ed25519 identities** so a peer can prove ownership of its persistent ID.
- **Nonce-based authentication** to prevent simply claiming someone else's ID.
- **Local peer-key pinning** so an already-trusted ID cannot silently switch to a different key.
- Optional **TLS certificate fingerprint pinning** for an additional verification layer.

The private identity key remains on the device.

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

Join a host discovered on your LAN:

```text
cmd-chat join cc-XXXXXXXXXXXXXXX
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
cmd/cmd-chat/        the chat tool users actually run
clients/chromeos/    ChromeOS terminal-style frontend
internal/chat/       chat connections and message protocol
internal/auth/       peer authentication and trust
internal/identity/   persistent device identity
internal/discovery/  LAN host discovery
internal/network/    connectivity and NAT-related networking
internal/ipc/        local ChromeOS-to-Go bridge
scripts/             setup/build helpers
.github/workflows/   cross-platform CI
```

## What this project is

CMD-Chat is **not trying to be another Discord, Slack, or hosted messaging platform.**

It is a small tool for one specific idea:

> **If two computers want to chat, let one of those computers host the conversation.**

The rest of the project exists to make that idea reliable, portable, and secure.

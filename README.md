# CMD-Chat

**A serverless chat tool for talking directly to another computer.**

> **Normal user? Don't download the source code. Download the latest release, extract it, and double-click `CMD-Chat.exe` (Windows) or the included launcher for your platform.**
>
> **Start here: [`docs/QUICKSTART.md`](docs/QUICKSTART.md)**

CMD-Chat is built around a simple idea: **you should be able to open a chat with another person without signing up for an account, running a permanent chat server, or handing your messages to a central service.**

When someone hosts a chat, **their own computer temporarily becomes the chat server**. When the chat closes, that host server is gone.

The normal application now opens a simple graphical interface automatically. The terminal commands remain available for developers and advanced users.

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
```

## What using it feels like

### Host

Open CMD-Chat and click **Start a Chat**. The app gives you your persistent ID and a button to copy it.

Send that ID to your friend and leave CMD-Chat open.

### Join

Open CMD-Chat and click **Join a Chat**. Paste your friend's ID and click **Join**.

If both computers are on the same LAN, CMD-Chat can discover the host automatically.

The exact connection path can vary depending on the network. Across different networks, firewall and NAT rules can prevent a direct connection.

## Your ID stays the same

Your CMD-Chat ID is **not your IP address**.

Every installation has a persistent Ed25519 identity. Its public key determines the ID, so changing Wi-Fi networks, moving locations, or getting a new IP address does not change who you are.

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

## Downloading and launching

For regular users, use a release package rather than the source repository.

Each release contains ready-to-run builds for:

- Windows x64
- macOS Intel
- macOS Apple Silicon
- Linux x64
- Linux ARM64

Extract the package and launch CMD-Chat. No Go or Python installation is required for release builds.

## Developer build

Install Go 1.23+:

```bash
go test ./...
go build ./cmd/cmd-chat
```

Or use the bootstrap script:

```bash
python3 scripts/install.py
```

The compiled program opens the graphical interface when launched without arguments.

## Terminal usage

The GUI is the default, but the original command-line interface is still available:

```text
cmd-chat id
cmd-chat host
cmd-chat join cc-XXXXXXXXXXXXXXX
cmd-chat join --address HOST:38556 --fingerprint SHA256_CERT_FINGERPRINT
cmd-chat gui
```

## Project structure

```text
cmd/cmd-chat/        main application + click-to-launch GUI
cmd/cmd-chat/ui/     embedded browser interface
clients/             additional client/front-end code
internal/             chat, identity, discovery, network, auth, IPC
scripts/              developer setup/build helpers
launchers/            double-click launchers for source/build folders
docs/                 user documentation
.github/workflows/    automated tests and release builds
go.mod               Go module definition
README.md             project overview
```

## What this project is

CMD-Chat is **not trying to be another Discord, Slack, or hosted messaging platform.**

It is a small tool for one specific idea:

> **If two computers want to chat, let one of those computers host the conversation.**

The rest of the project exists to make that idea reliable, portable, secure, and easy to launch.

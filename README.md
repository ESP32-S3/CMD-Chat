# CMD-Chat

A small cross-platform terminal chat utility built around temporary host-owned chat servers.

## Core model

- Every installation gets a persistent ID that is independent of its IP address.
- A host computer temporarily acts as the chat server while the app is open.
- Clients connect directly to that host.
- There is no central account service, message database, or permanent chat backend.
- LAN discovery uses UDP broadcast and never carries chat messages.
- Chat transport uses TLS 1.3.
- Host fingerprints can be pinned to prevent an unexpected endpoint from being trusted.

## Current connection paths

### Same Wi-Fi / LAN

```text
Guest
  |
  | UDP broadcast: "find ID cc-..."
  v
Host
  |
  | direct TCP + TLS 1.3
  v
Chat
```

The guest can join using the host's persistent ID without knowing its LAN IP first.

### Different networks

A direct connection is supported when the host is reachable from the guest, such as with a public IPv6 address or a forwarded TCP port:

```text
Guest -> Internet -> Host public address:38556 -> TLS chat
```

The project does **not** claim that a permanent ID alone can locate a host behind arbitrary NATs. That requires a rendezvous mechanism, and some NAT/firewall combinations also require a relay. Adding those mechanisms would introduce infrastructure outside the host machine, so they are not silently included in the current serverless core.

The transport layer is deliberately separated from chat and discovery so a future optional NAT-traversal/rendezvous module can be added without changing the message protocol.

## Cross-platform

The project is written in Go and targets:

- Windows / CMD / PowerShell
- Linux terminals
- macOS Terminal
- amd64 and arm64 release binaries

GitHub Actions tests on Windows, Linux, and macOS and can build release binaries from version tags.

## Build

Install Go 1.23+:

```bash
go build ./cmd/cmd-chat
```

Windows:

```powershell
go build -o cmd-chat.exe ./cmd/cmd-chat
```

Run tests:

```bash
go test ./...
```

## Usage

Show your persistent ID:

```text
cmd-chat id
```

Host a temporary chat server:

```text
cmd-chat host
```

The host prints its TLS fingerprint. Keep that value with the connection details you share with a guest.

Join a host on the same LAN:

```text
cmd-chat join cc-XXXXXXXXXXXXXXX
```

Join a directly reachable host on another network:

```text
cmd-chat join --address HOST:38556 --fingerprint SHA256_CERT_FINGERPRINT
```

If you intentionally do not pin the fingerprint, the client warns you and still establishes the encrypted TLS channel:

```text
cmd-chat join --address HOST:38556
```

Inside a chat, type `/quit` to leave.

## Security notes

TLS protects chat contents in transit. Fingerprint pinning protects against connecting to a different endpoint than the one whose fingerprint you verified out of band.

The current host certificate is generated when a host session starts, so its fingerprint is session-specific. The persistent user ID is separate from that certificate and remains unchanged across network changes.

## Repository layout

```text
cmd/cmd-chat/       terminal application
internal/chat/      TLS chat server/client and message protocol
internal/discovery/ LAN UDP discovery
internal/identity/  persistent installation ID
.github/workflows/  cross-platform CI and release builds
```

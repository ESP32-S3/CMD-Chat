# CMD-Chat

A small cross-platform terminal chat utility built around temporary host-owned chat servers.

## Core model

- Every installation gets a persistent **Ed25519 identity** whose ID is derived from its public key, not its IP address.
- A host computer temporarily acts as the chat server while the app is open.
- Clients connect directly to that host when the network permits it.
- There is no central account service, message database, or permanent chat backend in the core.
- LAN discovery uses UDP broadcast and never carries chat messages.
- Chat transport uses TLS 1.3.
- Peers mutually authenticate with nonce-based Ed25519 challenge/response.
- Successfully authenticated peer public keys are pinned locally (TOFU); a later key change for the same ID is rejected.

## Connection paths

### Same Wi-Fi / LAN

```text
Guest
  |
  | UDP broadcast: "find ID cc-..."
  v
Host
  |
  | direct TCP + TLS 1.3 + Ed25519 authentication
  v
Chat
```

The guest can join using the host's persistent ID without knowing its LAN IP first.

### Different networks

A direct connection is supported when the host is reachable from the guest, such as with a public IPv6 address or a forwarded TCP port:

```text
Guest -> Internet -> Host public address:38556 -> TLS chat -> Ed25519 auth
```

The `internal/network/nat` package also provides STUN public-endpoint discovery and UDP hole-punch probes. Hole punching requires both peers to exchange candidates through a rendezvous mechanism; the core project intentionally does not run that rendezvous service.

Some NAT/firewall combinations cannot be connected directly. `internal/network/relay` defines an optional relay interface for a future externally operated relay. A relay would forward encrypted traffic only; it would not become the chat server or identity authority.

This means the core remains serverless in the sense that **the host device is the chat server**. It does not promise impossible universal connectivity with zero infrastructure.

## Security

- TLS 1.3 encrypts chat traffic in transit.
- Each installation has a persistent Ed25519 keypair. The private key stays on the device.
- The peer proves private-key possession using a fresh 32-byte nonce.
- The claimed ID is verified against the SHA-256 hash of the public key.
- Peer keys are pinned in the local trusted-peer store after the first successful authenticated connection. If an existing ID presents a different key, the connection is rejected.
- TLS certificate fingerprints can additionally be pinned out-of-band.

This is a security-oriented prototype, not a formally audited secure messenger.

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
go test ./...
```

Windows:

```powershell
go build -o cmd-chat.exe ./cmd/cmd-chat
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

The host prints its TLS certificate fingerprint.

Join a host on the same LAN:

```text
cmd-chat join cc-XXXXXXXXXXXXXXX
```

Join a directly reachable host on another network:

```text
cmd-chat join --address HOST:38556 --fingerprint SHA256_CERT_FINGERPRINT
```

If you intentionally do not pin the TLS fingerprint, the client warns you. The Ed25519 identity handshake is still mandatory.

The NAT package can discover a public UDP endpoint for diagnostics/future rendezvous integration.

Inside a chat, type `/quit` to leave.

## Repository layout

```text
cmd/cmd-chat/       terminal application
internal/chat/      TLS chat server/client and authenticated message protocol
internal/auth/      Ed25519 challenge/response and trusted-peer storage
internal/discovery/ LAN UDP discovery
internal/identity/  persistent Ed25519 installation identity
internal/network/   connection strategy, STUN/NAT traversal, relay interface
.github/workflows/  cross-platform CI and release builds
```

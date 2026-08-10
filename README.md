# CMD-Chat

A small cross-platform terminal chat utility built around temporary host-owned chat servers.

## What it does now

- Windows, macOS, and Linux via Go.
- Runs directly in a terminal/CMD.
- Generates a persistent device ID that does not change when the network changes.
- One machine can host the chat temporarily.
- Multiple peers can connect to the host.
- LAN discovery lets a peer enter the host's persistent ID instead of an IP address.
- Same-LAN traffic uses a direct TCP connection to the host.
- Chat traffic is protected with TLS 1.3 and a host certificate fingerprint can be pinned.
- No database or permanent chat server is required.

## Networking model

```text
Same LAN:
Guest -> UDP discovery -> Host LAN address -> TLS chat -> Host

Different networks:
Guest -> Host public address/port -> TLS chat -> Host
```

For an Internet connection, the host must currently be reachable from the guest (for example, a public IPv6 address or a forwarded TCP port). NAT traversal/rendezvous is intentionally not faked: arbitrary NATs can make direct serverless connectivity impossible without some third-party rendezvous or relay mechanism.

That limitation is documented so the implementation stays honest. A future transport layer can add optional NAT traversal without changing the chat protocol.

## Build

Install Go 1.23+ and run:

```bash
go build -o cmd-chat ./cmd/cmd-chat
```

On Windows:

```powershell
go build -o cmd-chat.exe ./cmd/cmd-chat
```

## Run

Show your persistent ID:

```text
cmd-chat id
```

Host:

```text
cmd-chat host
```

Join a host on the same LAN:

```text
cmd-chat join cc-XXXXXXXXXXXXXXX
```

Join a directly reachable host on another network:

```text
cmd-chat join --address HOST:38556 --fingerprint SHA256_CERT_FINGERPRINT
```

Inside a chat, type `/quit` to leave.

## Design

The persistent ID identifies the installation; it is deliberately not an IP address. Network addresses are temporary connection details. This separation allows the same ID to remain valid after a device changes Wi-Fi, ISP, or location.

The host is the actual chat server. LAN discovery is only a local UDP lookup and carries no chat messages. There is currently no central account service, message database, or hosted chat backend.

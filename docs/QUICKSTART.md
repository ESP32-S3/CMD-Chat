# CMD-Chat Quick Start

**For people who just want to chat.**

## Windows: just double-click

If you downloaded a ready-to-run release, find:

**`Start CMD-Chat.bat`**

Double-click it.

A normal Windows terminal opens with CMD-Chat. **The chat interface stays entirely in the terminal.**

You should not need to open a Python file, install Go, or guess which program to run when using a release build.

## Windows will ask about the firewall — click "Allow access"

The first time you open CMD-Chat, Windows shows:

```text
Windows Defender Firewall has blocked some features of this app
```

Click **Allow access**, and tick **Private networks** if it offers the choice. CMD-Chat needs it to accept direct connections from your friend.

If you click Cancel, CMD-Chat still works — it falls back to the encrypted relay and tells you so. To change your mind later:

**Windows Security → Firewall & network protection → Allow an app through firewall → Change settings →** find CMD-Chat and tick it.

## There is no "start" and no "join"

Both people just open CMD-Chat. That's it.

From the moment it opens, you are reachable. CMD-Chat shows your ID:

```text
========================================
              CMD-Chat
========================================
Your ID: cc-K7F4A92D3B1E

You are reachable now. Nobody has to "start" or "join" anything.
Send your ID to a friend, or paste theirs below - whoever types the
other's ID first connects, and the other side just waits here.
```

**Send your ID to your friend.** They send you theirs.

Then **whoever pastes the other's ID first** makes the connection. The other person does nothing at all — the chat just opens in front of them:

```text
cc-P3J4TL57W5LFTPFS connected to you.
Type messages below. /quit leaves the chat.
```

You don't have to agree in advance about who does it. If you both have CMD-Chat open, either of you can start the conversation at any time.

## Chatting

Type a message and press **Enter**.

## Leave

Type:

```text
/quit
```

That leaves the chat and takes you back to the prompt — **you stay reachable**, so the same person (or someone else) can connect again. Type `/quit` again to close CMD-Chat.

## Other things you can type

```text
?        help
/id      show your ID again
/debug   open a debug terminal that records a crash log
/quit    leave a chat, or close CMD-Chat
```

### Important

- Both people need CMD-Chat open while chatting.
- Whoever gets connected *to* is temporarily hosting the chat from their own computer.
- Same-Wi-Fi connections are usually the easiest.
- If you're on different networks and it won't connect, check that the other person actually has CMD-Chat open.

## macOS and Linux

The release ZIP includes a launcher beside the `CMD-Chat` program:

- **macOS:** `Start CMD-Chat.command`
- **Linux:** `Start-CMD-Chat.sh`

Run the launcher instead of hunting for the executable. The interface is still the terminal.

## If something goes wrong

If CMD-Chat closes unexpectedly, the launcher now holds the window open and shows the reason. Type `/debug` at the prompt to open a second terminal that records a crash log, then reproduce the problem there and attach the log to a bug report.

## If you downloaded the source code

The source repository is mainly for developers. A source checkout is **not** the same thing as a ready-to-run release.

To build it yourself, see the build instructions in the main `README.md`.

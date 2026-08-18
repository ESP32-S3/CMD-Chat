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

## Update notices

When CMD-Chat opens, it asks GitHub whether a newer release exists. If one does, it tells you once:

```text
A newer CMD-Chat is available: v2.1.6 (you have v2.1.5).
Download it from https://github.com/ESP32-S3/CMD-Chat/releases/tag/v2.1.6
You can keep chatting on this version; updating is optional.
```

It never installs anything, never interrupts a chat, and **sends nothing about you** — it only asks what the newest version is. If GitHub is unreachable, CMD-Chat says nothing and carries on.

To turn it off, set the environment variable `CMD_CHAT_NO_UPDATE_CHECK=1`.

## Pick a nickname

By default you show up as your Windows or Mac account name. To change it:

```text
/nick Alex
```

Everyone in a chat sees **Alex** next to your messages from then on.

Your nickname is stored **on your own computer only**. It is not in the phonebook, not in any database, and nobody can look it up from your ID. It travels only to the people you are actually chatting with, inside the encrypted connection.

Type `/nick` with nothing after it to go back to your account name.

## Group chats

More than one person can join you at once, and everyone in the room sees everyone else.

There is nothing to set up. Whoever gets connected to first is hosting the room, and **the room is that person's ID**.

To add a third person, type:

```text
/invite
```

CMD-Chat shows the ID to share. This matters: if you joined someone else, the ID to share is **theirs**, not yours — sharing your own would start a separate chat with you instead. `/invite` tells you which is which.

To see who is in the room:

```text
/who
```

You will see people arrive and leave:

```text
* Jordan joined - 3 here
* Sam left - 2 here
```

### Turning group chat off

If you are hosting and want one-to-one only:

```text
/group off
```

Anyone already in the room stays; the next person who tries is told you are not accepting others. Turn it back on with `/group on`. The setting is remembered on your computer.

Only the host of a room controls this.

## Other things you can type

```text
?              help
/id            show your ID again
/nick NAME     set the name others see
/who           list who is in the room
/invite        show the ID that invites someone into this room
/group on|off  allow more than one person in (host only)
/debug         open a debug terminal that records a crash log
/quit          leave a chat, or close CMD-Chat
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

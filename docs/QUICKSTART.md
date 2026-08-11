# CMD-Chat Quick Start

**For people who don't want to deal with technical crap.**

## 1. Install it

Download CMD-Chat and make sure **Go 1.23+** is installed.

From the CMD-Chat folder, run:

**Windows:**
```bat
python scripts/install.py
```

**Mac / Linux:**
```bash
python3 scripts/install.py
```

The installer builds CMD-Chat for you.

## 2. Start a chat

One person runs:

```text
cmd-chat host
```

You'll get a code like:

```text
cc-K7F4A92D3B1E
```

**Send that code to your friend.**

## 3. Join

Your friend runs:

```text
cmd-chat join cc-K7F4A92D3B1E
```

Replace the example code with the one you received.

Once it says you're connected, type your message and press **Enter**.

## 4. Leave

Type:

```text
/quit
```

That's it.

### A couple things to know

- Both people need CMD-Chat running while chatting.
- The person who uses `host` temporarily hosts the chat from their own computer.
- Same-Wi-Fi connections are usually the easiest.
- If you're on different networks and it won't connect, a firewall or router may be blocking the connection.

# CMD-Chat Quick Start

**For people who don't want to deal with technical crap.**

## If you downloaded a release

You **do not need Go or Python**.

1. Download the CMD-Chat package for your computer.
2. Extract the ZIP.
3. Open the extracted folder.
4. **Windows:** double-click `CMD-Chat.exe`.
5. **macOS:** double-click `Start CMD-Chat.command`.
6. **Linux:** double-click `Start-CMD-Chat.sh` if your file manager allows scripts to run, or run it from your terminal.

CMD-Chat opens its simple interface in your normal web browser.

## Start a chat

Click **Start a Chat**.

You'll get a code like:

```text
cc-K7F4A92D3B1E
```

Click **Copy code** and send it to your friend.

Leave CMD-Chat open while you wait.

## Join a chat

Click **Join a Chat**.

Paste your friend's code and click **Join**.

If both computers are on the same Wi-Fi/LAN, CMD-Chat can automatically find the host.

Once connected, type a message and click **Send**.

## Leave

Use **Back** to stop the current chat, or close the CMD-Chat browser window when you're done.

### If it won't connect

- Make sure the other person has CMD-Chat open.
- Double-check the ID you pasted.
- Same-Wi-Fi connections are usually the easiest.
- Different networks can be blocked by a firewall or router.

## If you downloaded the source code

Source-code users are the exception. Install **Go 1.23+**, then run the installer from the repository folder:

**Windows:**
```bat
python scripts/install.py
```

**Mac / Linux:**
```bash
python3 scripts/install.py
```

The installer builds the ready-to-run CMD-Chat executable in `bin/`.

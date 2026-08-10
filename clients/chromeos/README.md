# CMD-Chat ChromeOS Client

This client provides a terminal-style window for ChromeOS devices.

Run:

```bash
python3 cmd_chat.py
```

It uses Tkinter and is intended as a frontend for the CMD-Chat networking core.

The design keeps the same architecture:

```
ChromeOS GUI
     |
     v
CMD-Chat Core
     |
     +-- Identity
     +-- Encryption
     +-- Networking
```

This is useful for devices where a normal native terminal experience is not ideal.

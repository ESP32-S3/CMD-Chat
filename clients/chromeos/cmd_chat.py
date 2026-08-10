#!/usr/bin/env python3
"""ChromeOS-friendly CMD-Chat frontend backed by the local Go core."""

from __future__ import annotations

import json
import platform
import socket
import tkinter as tk
from threading import Thread
from tkinter import scrolledtext

HOST = "127.0.0.1"
PORT = 5050


class CmdChatWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CMD-Chat ChromeOS")
        self.root.geometry("800x500")
        self.sock: socket.socket | None = None
        self.reader = None

        self.output = scrolledtext.ScrolledText(
            self.root, bg="black", fg="white", insertbackground="white",
            font=("monospace", 12),
        )
        self.output.pack(expand=True, fill="both")
        self.input = tk.Entry(
            self.root, bg="black", fg="white", insertbackground="white",
            font=("monospace", 12),
        )
        self.input.pack(fill="x")
        self.input.bind("<Return>", self.send)

        self.write("CMD-Chat ChromeOS Client")
        self.write(f"Platform: {platform.system()}")
        self.write("Connecting to local CMD-Chat core...")
        Thread(target=self.connect, daemon=True).start()

    def write(self, text: str) -> None:
        self.root.after(0, self._write, text)

    def _write(self, text: str) -> None:
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def connect(self) -> None:
        try:
            self.sock = socket.create_connection((HOST, PORT), timeout=5)
            self.reader = self.sock.makefile("r", encoding="utf-8")
            self.write("✓ Connected to CMD-Chat core")
            self.sock.sendall((json.dumps({"cmd": "status"}) + "\n").encode())
            Thread(target=self.receive, daemon=True).start()
        except OSError as exc:
            self.write(f"✗ Core unavailable: {exc}")
            self.write("Start the CMD-Chat host first, then launch this client.")

    def receive(self) -> None:
        try:
            for line in self.reader:
                event = json.loads(line)
                if event.get("type") == "msg":
                    self.write(f"[{event.get('name', 'peer')}] {event.get('message', '')}")
                elif event.get("message"):
                    self.write(event["message"])
        except (OSError, json.JSONDecodeError) as exc:
            self.write(f"Connection closed: {exc}")

    def send(self, _event=None) -> None:
        message = self.input.get().strip()
        self.input.delete(0, "end")
        if not message or not self.sock:
            return
        try:
            self.sock.sendall((json.dumps({"cmd": "send", "message": message}) + "\n").encode())
        except OSError as exc:
            self.write(f"Send failed: {exc}")

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    CmdChatWindow().run()

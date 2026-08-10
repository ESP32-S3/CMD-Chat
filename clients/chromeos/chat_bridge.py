#!/usr/bin/env python3
"""ChromeOS frontend bridge for CMD-Chat.

The UI talks only to the local Go core. The Go core owns networking,
identity, encryption, and peer connections.
"""

from __future__ import annotations

import json
import socket
import tkinter as tk
from threading import Thread

HOST = "127.0.0.1"
PORT = 5050


class ChatBridge:
    def __init__(self):
        self.sock = None
        self.file = None

    def connect(self):
        self.sock = socket.create_connection((HOST, PORT), timeout=5)
        self.file = self.sock.makefile("r", encoding="utf-8")

    def send(self, payload: dict):
        if self.sock:
            self.sock.sendall((json.dumps(payload) + "\n").encode())

    def listen(self, callback):
        if not self.file:
            return
        for line in self.file:
            callback(json.loads(line))


class App:
    def __init__(self):
        self.bridge = ChatBridge()
        self.window = tk.Tk()
        self.window.title("CMD-Chat ChromeOS")

        self.output = tk.Text(self.window)
        self.output.pack(expand=True, fill="both")

        self.input = tk.Entry(self.window)
        self.input.pack(fill="x")
        self.input.bind("<Return>", self.send)

        Thread(target=self.start_bridge, daemon=True).start()

    def start_bridge(self):
        try:
            self.bridge.connect()
            self.write("Connected to CMD-Chat core")
            Thread(target=self.bridge.listen, args=(self.write,), daemon=True).start()
        except Exception as e:
            self.write("Core unavailable: " + str(e))

    def send(self, _event=None):
        msg = self.input.get()
        self.input.delete(0, tk.END)
        self.bridge.send({"cmd": "send", "message": msg})

    def write(self, message):
        self.output.insert(tk.END, json.dumps(message) if isinstance(message, dict) else message)
        self.output.insert(tk.END, "\n")

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    App().run()

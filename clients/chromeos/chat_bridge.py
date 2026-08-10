#!/usr/bin/env python3
"""ChromeOS frontend bridge for CMD-Chat.

This module keeps the Tkinter frontend separate from the networking core.
The Go client can expose a local IPC endpoint and this UI can connect to it.
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

    def connect(self):
        self.sock = socket.create_connection((HOST, PORT), timeout=5)

    def send(self, message: str):
        if self.sock:
            self.sock.sendall((json.dumps({"type": "message", "data": message}) + "\n").encode())


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
        except Exception as e:
            self.write("Waiting for CMD-Chat core: " + str(e))

    def send(self, _event=None):
        msg = self.input.get()
        self.input.delete(0, tk.END)
        self.write("> " + msg)
        self.bridge.send(msg)

    def write(self, text):
        self.output.insert(tk.END, text + "\n")

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    App().run()

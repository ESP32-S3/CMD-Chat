#!/usr/bin/env python3
"""ChromeOS-friendly CMD-Chat terminal-style frontend.

This is a lightweight GUI wrapper intended for devices where a native terminal
experience is inconvenient. The networking core can be connected here without
changing the user interface.
"""

import tkinter as tk
from tkinter import scrolledtext
import platform


class CmdChatWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CMD-Chat")
        self.root.geometry("800x500")

        self.output = scrolledtext.ScrolledText(
            self.root,
            bg="black",
            fg="white",
            insertbackground="white",
            font=("monospace", 12),
        )
        self.output.pack(expand=True, fill="both")

        self.input = tk.Entry(self.root, bg="black", fg="white", insertbackground="white", font=("monospace", 12))
        self.input.pack(fill="x")
        self.input.bind("<Return>", self.send)

        self.write("CMD-Chat ChromeOS Client")
        self.write(f"Platform: {platform.system()}")
        self.write("")
        self.write("This frontend is ready for the CMD-Chat networking core.")
        self.write("> ")

    def write(self, text):
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def send(self, _event=None):
        message = self.input.get()
        self.input.delete(0, "end")
        if message:
            self.write("> " + message)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    CmdChatWindow().run()

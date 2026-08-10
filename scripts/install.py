#!/usr/bin/env python3
"""Install/build CMD-Chat dependencies and binary.

The project itself is Go. This script intentionally uses only Python's standard
library so it can bootstrap the environment without pip dependencies.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, text=True, check=check)


def version_ok() -> bool:
    go = shutil.which("go")
    if not go:
        return False
    try:
        out = subprocess.check_output([go, "version"], text=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    # Go version output is enough for a clear prerequisite check; avoid
    # installing anything automatically because package-manager behavior is
    # platform-specific and may require administrator privileges.
    print(out.strip())
    return True


def main() -> int:
    print("CMD-Chat installer")
    print(f"Platform: {platform.system()} {platform.machine()}")

    if not version_ok():
        print("\nGo was not found on PATH.")
        print("Install Go 1.23 or newer, then run this script again:")
        print("  https://go.dev/dl/")
        return 1

    run(["go", "mod", "download"])
    run(["go", "test", "./..."])

    binary_dir = ROOT / "bin"
    binary_dir.mkdir(exist_ok=True)
    binary = binary_dir / ("cmd-chat.exe" if os.name == "nt" else "cmd-chat")
    run(["go", "build", "-o", str(binary), "./cmd/cmd-chat"])

    print(f"\n✓ Build complete: {binary}")
    if os.name == "nt":
        print(f"Run: {binary}")
    else:
        print(f"Run: ./{binary.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

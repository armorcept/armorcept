#!/usr/bin/env python3
"""Appends ArmorCept decision-log lines (JSONL on stdin) to a file.

Usage: decision_log.py <path> <max_bytes>

Rotates <path> to <path>.1 (keeping one old file) when the append would take
it past max_bytes. max_bytes of 0 disables rotation. Uses only the standard
library so it runs with `python3 -I -S`.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: decision_log.py <path> <max_bytes>\n")
        return 2
    path = sys.argv[1]
    max_bytes = int(sys.argv[2])
    data = sys.stdin.buffer.read()
    if not data:
        return 0

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)

    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        size = 0
    if max_bytes > 0 and size > 0 and size + len(data) > max_bytes:
        os.replace(path, path + ".1")

    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())

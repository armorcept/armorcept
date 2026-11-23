"""Tests for python/decision_log.py (append, permissions, rotation)."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest

WRITER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python", "decision_log.py")


def append(path: str, data: str, max_bytes: int) -> None:
    subprocess.run(
        [sys.executable, "-I", "-S", WRITER, path, str(max_bytes)],
        input=data.encode(),
        check=True,
    )


class DecisionLogWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "nested", "decisions.jsonl")

    def test_appends_and_creates_private_file(self) -> None:
        append(self.path, '{"a":1}\n', 0)
        append(self.path, '{"a":2}\n', 0)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), '{"a":1}\n{"a":2}\n')
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_rotates_past_max_bytes_keeping_one_old_file(self) -> None:
        line = '{"n":"' + "x" * 40 + '"}\n'
        for _ in range(3):
            append(self.path, line, 100)
        with open(self.path + ".1", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), line * 2)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), line)
        for _ in range(2):
            append(self.path, line, 100)
        self.assertFalse(os.path.exists(self.path + ".2"))
        self.assertLessEqual(os.path.getsize(self.path), 100)

    def test_empty_input_is_a_no_op(self) -> None:
        append(self.path, "", 0)
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()

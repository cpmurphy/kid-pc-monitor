"""Tests for the shared web panel SQLite connection."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db


class PanelDbTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", self.db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_context_manager_closes_connection(self) -> None:
        with panel_db.connect() as conn:
            conn.execute("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

    def test_repeated_connections_do_not_accumulate_handles(self) -> None:
        fd_dir = Path("/proc/self/fd")
        if not fd_dir.is_dir():
            self.skipTest("open-file accounting requires /proc/self/fd")

        def db_handles() -> int:
            needle = str(self.db_path)
            count = 0
            for entry in fd_dir.iterdir():
                try:
                    target = os.readlink(entry)
                except OSError:
                    continue
                if needle in target:
                    count += 1
            return count

        before = db_handles()
        for _ in range(50):
            with panel_db.connect() as conn:
                conn.execute("SELECT 1")
        self.assertEqual(db_handles(), before)


if __name__ == "__main__":
    unittest.main()

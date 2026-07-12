"""Tests for reverse agent heartbeat persistence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_sync_store as store
from kid_pc_monitor import panel_db


class AgentSyncStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", self.db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_record_agent_poll_and_lookup_by_ip(self) -> None:
        store.record_agent_poll(
            "KidPC",
            "192.168.1.10",
            {"hostname": "KidPC", "status": "UNLOCKED", "reachable": True},
        )

        agent = store.recent_agent_for_ip("192.168.1.10")

        assert agent is not None
        self.assertEqual(agent["hostname"], "KidPC")
        self.assertEqual(agent["ip"], "192.168.1.10")
        self.assertEqual(agent["status"], "UNLOCKED")

    def test_recent_agent_for_hostname(self) -> None:
        store.record_agent_poll(
            "KidPC",
            "192.168.1.10",
            {"hostname": "KidPC", "status": "LOCKED", "reachable": True},
        )

        agent = store.recent_agent_for_hostname("KidPC")

        assert agent is not None
        self.assertEqual(agent["ip"], "192.168.1.10")
        self.assertEqual(agent["status"], "LOCKED")


if __name__ == "__main__":
    unittest.main()

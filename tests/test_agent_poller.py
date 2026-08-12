"""Tests for background agent registry pruning."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_poller, panel_db, scan_store


def _sample_pc_info(**overrides: object) -> dict:
    base: dict = {
        "ip": "192.168.1.10",
        "hostname": "KidPC",
        "status": "UNLOCKED",
        "locked": False,
        "current_user": "child",
        "daily_limit": 120,
        "reachable": True,
    }
    base.update(overrides)
    return base


class AgentPollerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", self.db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_poll_once_prunes_stale_tracked_ips(self) -> None:
        scan_store.record_poll_inspect(
            "192.168.1.10",
            _sample_pc_info(ip="192.168.1.10"),
            when=datetime.now().astimezone() - timedelta(hours=13),
        )
        with mock.patch.object(
            agent_poller, "prune_stale_tracked_ips", wraps=scan_store.prune_stale_tracked_ips
        ) as prune_mock:
            agent_poller.poll_once()
        prune_mock.assert_called_once_with()
        self.assertEqual(scan_store.get_tracked_ips(), {})

    def test_poll_once_keeps_recent_tracked_ips(self) -> None:
        scan_store.record_poll_inspect(
            "192.168.1.10",
            _sample_pc_info(ip="192.168.1.10"),
            when=datetime.now().astimezone() - timedelta(hours=1),
        )
        agent_poller.poll_once()
        self.assertIn("192.168.1.10", scan_store.get_tracked_ips())

    def test_poll_once_does_not_dial_agents(self) -> None:
        scan_store.record_poll_inspect(
            "192.168.1.10",
            _sample_pc_info(ip="192.168.1.10"),
        )
        with mock.patch("socket.create_connection") as connect_mock:
            agent_poller.poll_once()
        connect_mock.assert_not_called()

    def test_poll_once_no_targets(self) -> None:
        with mock.patch.object(
            agent_poller, "prune_stale_tracked_ips", return_value=[]
        ) as prune_mock:
            agent_poller.poll_once()
        prune_mock.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

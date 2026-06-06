"""Tests for background agent polling."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_poller, panel_db, scan_store, snapshot_store


def _sample_pc_info(**overrides: object) -> dict:
    base: dict = {
        "ip": "192.168.1.10",
        "port": 9999,
        "hostname": "KidPC",
        "status": "UNLOCKED",
        "locked": False,
        "current_user": "child",
        "daily_limit": 120,
        "usage_limit": 120,
        "accumulated_seconds": 1800,
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

    def test_poll_once_saves_reachable_snapshot(self) -> None:
        scan_store.save_scan(
            pcs={"192.168.1.10": {"hostname": "KidPC", "reachable": True}},
            scanned_at=datetime.now().astimezone(),
            network_label="lan",
            subnet="192.168.1.0/24",
        )
        with mock.patch.object(
            agent_poller, "inspect_pc", return_value=_sample_pc_info()
        ) as inspect_mock:
            agent_poller.poll_once()
        inspect_mock.assert_called_once_with("192.168.1.10")
        result = snapshot_store.get_latest_snapshot_for_pc(ip="192.168.1.10")
        self.assertIsNotNone(result)
        dashboard, _last_poll_at = snapshot_store.get_dashboard_pcs()
        self.assertTrue(dashboard["192.168.1.10"]["reachable"])

    def test_poll_once_saves_unreachable_snapshot(self) -> None:
        scan_store.save_scan(
            pcs={"192.168.1.10": {"hostname": "KidPC", "reachable": True}},
            scanned_at=datetime.now().astimezone(),
            network_label="lan",
            subnet="192.168.1.0/24",
        )
        with mock.patch.object(
            agent_poller,
            "inspect_pc",
            side_effect=ConnectionError("Cannot reach agent at 192.168.1.10:9999: timeout"),
        ):
            agent_poller.poll_once()
        dashboard, _last_poll_at = snapshot_store.get_dashboard_pcs()
        self.assertFalse(dashboard["192.168.1.10"]["reachable"])
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 1)

    def test_poll_once_no_targets(self) -> None:
        with mock.patch.object(agent_poller, "inspect_pc") as inspect_mock:
            agent_poller.poll_once()
        inspect_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

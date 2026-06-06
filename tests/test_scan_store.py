"""Tests for web panel scan persistence."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db
from kid_pc_monitor import scan_store as store


def _sample_pc_info(**overrides: object) -> dict:
    base: dict = {
        "ip": "192.168.1.10",
        "port": 9999,
        "hostname": "KidPC",
        "status": "UNLOCKED",
        "locked": False,
        "current_user": "child",
        "daily_limit": 120,
        "reachable": True,
    }
    base.update(overrides)
    return base


class ScanStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", self.db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_save_scan_stores_unreachable_pc(self) -> None:
        store.save_scan(
            pcs={
                "192.168.1.10": _sample_pc_info(
                    reachable=False, connection_error="offline", ip="192.168.1.10"
                )
            },
            scanned_at=datetime.now().astimezone(),
            network_label="192.168.1.0/24",
            subnet="",
        )
        pcs = store.get_discovered_pcs()
        self.assertIn("192.168.1.10", pcs)
        self.assertFalse(pcs["192.168.1.10"]["reachable"])
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 0)

    def test_get_discovered_pcs_from_last_scan(self) -> None:
        store.save_scan(
            pcs={"192.168.1.10": _sample_pc_info(ip="192.168.1.10")},
            scanned_at=datetime.now().astimezone(),
            network_label="192.168.1.0/24",
            subnet="",
        )
        pcs = store.get_discovered_pcs()
        self.assertIn("192.168.1.10", pcs)
        self.assertEqual(pcs["192.168.1.10"]["hostname"], "KidPC")

    def test_load_scan_metadata(self) -> None:
        scanned_at = datetime.now().astimezone()
        store.save_scan(
            pcs={"10.0.0.1": _sample_pc_info(ip="10.0.0.1")},
            scanned_at=scanned_at,
            network_label="test-net",
            subnet="10.0.0.0/24",
        )
        meta = store.load_scan_metadata()
        self.assertEqual(meta["last_scan_network"], "test-net")
        self.assertEqual(meta["scan_subnet"], "10.0.0.0/24")
        self.assertIsNone(meta["scan_error"])

    def test_save_scan_error_keeps_discovered_pcs(self) -> None:
        store.save_scan(
            pcs={"10.0.0.1": _sample_pc_info(ip="10.0.0.1")},
            scanned_at=datetime.now().astimezone(),
            network_label="test-net",
            subnet="",
        )
        store.save_scan_error("bad subnet", subnet="bad")
        meta = store.load_scan_metadata()
        self.assertEqual(meta["scan_error"], "bad subnet")
        pcs = store.get_discovered_pcs()
        self.assertIn("10.0.0.1", pcs)
        self.assertEqual(pcs["10.0.0.1"]["hostname"], "KidPC")

    def test_multi_subnet_merge(self) -> None:
        store.save_scan(
            pcs={"10.0.0.1": _sample_pc_info(ip="10.0.0.1", hostname="SubnetA-PC")},
            scanned_at=datetime.now().astimezone(),
            network_label="subnet-a",
            subnet="10.0.0.0/24",
        )
        store.save_scan(
            pcs={"192.168.1.10": _sample_pc_info(ip="192.168.1.10", hostname="SubnetB-PC")},
            scanned_at=datetime.now().astimezone(),
            network_label="subnet-b",
            subnet="192.168.1.0/24",
        )
        pcs = store.get_tracked_ips()
        self.assertEqual(set(pcs.keys()), {"10.0.0.1", "192.168.1.10"})
        self.assertEqual(pcs["10.0.0.1"]["hostname"], "SubnetA-PC")
        self.assertEqual(pcs["192.168.1.10"]["hostname"], "SubnetB-PC")

    def test_rescan_same_ip_uses_latest_payload(self) -> None:
        store.save_scan(
            pcs={"10.0.0.1": _sample_pc_info(ip="10.0.0.1", hostname="OldName")},
            scanned_at=datetime.now().astimezone(),
            network_label="first",
            subnet="10.0.0.0/24",
        )
        store.save_scan(
            pcs={"10.0.0.1": _sample_pc_info(ip="10.0.0.1", hostname="NewName")},
            scanned_at=datetime.now().astimezone(),
            network_label="second",
            subnet="10.0.0.0/24",
        )
        pcs = store.get_tracked_ips()
        self.assertEqual(pcs["10.0.0.1"]["hostname"], "NewName")


if __name__ == "__main__":
    unittest.main()

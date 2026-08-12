"""Tests for web panel PC registry persistence (reverse-connected agents)."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db
from kid_pc_monitor import scan_store as store


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


class ScanStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", self.db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_record_poll_inspect_tracks_pc(self) -> None:
        store.record_poll_inspect("192.168.1.10", _sample_pc_info(ip="192.168.1.10"))
        pcs = store.get_tracked_ips()
        self.assertIn("192.168.1.10", pcs)
        self.assertEqual(pcs["192.168.1.10"]["hostname"], "KidPC")
        tracked = store.get_scan_pc("192.168.1.10")
        assert tracked is not None
        self.assertEqual(tracked["hostname"], "KidPC")

    def test_record_poll_inspect_stores_unreachable_pc(self) -> None:
        store.record_poll_inspect(
            "192.168.1.10",
            _sample_pc_info(reachable=False, connection_error="offline", ip="192.168.1.10"),
        )
        pcs = store.get_tracked_ips()
        self.assertIn("192.168.1.10", pcs)
        self.assertFalse(pcs["192.168.1.10"]["reachable"])
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 0)

    def test_record_poll_inspect_stores_hostname_column(self) -> None:
        store.record_poll_inspect("192.168.1.10", _sample_pc_info(ip="192.168.1.10"))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            hostname = conn.execute("SELECT hostname FROM scan_pcs").fetchone()[0]
        self.assertEqual(hostname, "KidPC")

    def test_ensure_schema_backfills_scan_pcs_hostname(self) -> None:
        payload = _sample_pc_info(ip="192.168.1.10", hostname="OldKidPC")
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    network_label TEXT NOT NULL,
                    subnet TEXT NOT NULL,
                    error TEXT
                );
                CREATE TABLE scan_pcs (
                    scan_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, ip)
                );
                """
            )
            conn.execute(
                """
                INSERT INTO scans (scanned_at, network_label, subnet, error)
                VALUES (?, ?, ?, ?)
                """,
                (datetime.now().astimezone().isoformat(timespec="seconds"), "poll", "", None),
            )
            conn.execute(
                "INSERT INTO scan_pcs (scan_id, ip, payload_json) VALUES (?, ?, ?)",
                (1, "192.168.1.10", json.dumps(payload)),
            )
            conn.commit()

            panel_db.ensure_schema(conn)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_pcs)")}
            hostname = conn.execute("SELECT hostname FROM scan_pcs").fetchone()[0]
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(scan_pcs)")}

        self.assertIn("hostname", columns)
        self.assertEqual(hostname, "OldKidPC")
        self.assertIn("idx_scan_pcs_hostname", indexes)
        migrated_pc = store.get_scan_pc_by_hostname("oldkidpc")
        assert migrated_pc is not None
        self.assertEqual(migrated_pc["ip"], "192.168.1.10")

    def test_multi_ip_merge(self) -> None:
        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1", hostname="SubnetA-PC"))
        store.record_poll_inspect(
            "192.168.1.10", _sample_pc_info(ip="192.168.1.10", hostname="SubnetB-PC")
        )
        pcs = store.get_tracked_ips()
        self.assertEqual(set(pcs.keys()), {"10.0.0.1", "192.168.1.10"})
        self.assertEqual(pcs["10.0.0.1"]["hostname"], "SubnetA-PC")
        self.assertEqual(pcs["192.168.1.10"]["hostname"], "SubnetB-PC")

    def test_get_scan_pc_by_hostname_uses_latest(self) -> None:
        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1", hostname="KidPC"))
        store.record_poll_inspect("10.0.0.2", _sample_pc_info(ip="10.0.0.2", hostname="KidPC"))

        pc = store.get_scan_pc_by_hostname("kidpc")

        assert pc is not None
        self.assertEqual(pc["ip"], "10.0.0.2")

    def test_prune_stale_tracked_ips_removes_old(self) -> None:
        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1"),
            when=datetime.now().astimezone() - timedelta(hours=13),
        )
        pruned = store.prune_stale_tracked_ips(max_age_hours=12)
        self.assertEqual(pruned, ["10.0.0.1"])
        self.assertEqual(store.get_tracked_ips(), {})

    def test_prune_stale_tracked_ips_keeps_recent(self) -> None:
        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1"),
            when=datetime.now().astimezone() - timedelta(hours=1),
        )
        pruned = store.prune_stale_tracked_ips(max_age_hours=12)
        self.assertEqual(pruned, [])
        self.assertIn("10.0.0.1", store.get_tracked_ips())

    def test_prune_stale_tracked_ips_keeps_recent_reachable_snapshot(self) -> None:
        from kid_pc_monitor import snapshot_store

        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1"),
            when=datetime.now().astimezone() - timedelta(hours=13),
        )
        snapshot_store.save_poll_snapshot(_sample_pc_info(ip="10.0.0.1", reachable=True))
        pruned = store.prune_stale_tracked_ips(max_age_hours=12)
        self.assertEqual(pruned, [])
        self.assertIn("10.0.0.1", store.get_tracked_ips())

    def test_prune_stale_tracked_ips_ignores_unreachable_snapshot(self) -> None:
        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1"),
            when=datetime.now().astimezone() - timedelta(hours=13),
        )
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots
                    (username, hostname, ip, snapshot_date, recorded_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "",
                    "KidPC",
                    "10.0.0.1",
                    datetime.now().astimezone().date().isoformat(),
                    datetime.now().astimezone().isoformat(timespec="seconds"),
                    '{"reachable": false, "ip": "10.0.0.1", "hostname": "KidPC"}',
                ),
            )
            conn.commit()
        pruned = store.prune_stale_tracked_ips(max_age_hours=12)
        self.assertEqual(pruned, ["10.0.0.1"])
        self.assertEqual(store.get_tracked_ips(), {})

    def test_failed_polls_do_not_keep_stale_ip_alive(self) -> None:
        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1"),
            when=datetime.now().astimezone() - timedelta(hours=13),
        )
        store.record_poll_inspect(
            "10.0.0.1",
            {"hostname": "KidPC", "ip": "10.0.0.1", "reachable": False},
        )
        store.record_poll_inspect(
            "10.0.0.1",
            {"hostname": "KidPC", "ip": "10.0.0.1", "reachable": False},
        )

        pruned = store.prune_stale_tracked_ips(max_age_hours=12)
        self.assertEqual(pruned, ["10.0.0.1"])
        self.assertEqual(store.get_tracked_ips(), {})

    def test_reachable_poll_refreshes_tracked_ip(self) -> None:
        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1"),
            when=datetime.now().astimezone() - timedelta(hours=13),
        )
        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1"))

        pruned = store.prune_stale_tracked_ips(max_age_hours=12)
        self.assertEqual(pruned, [])
        self.assertIn("10.0.0.1", store.get_tracked_ips())

    def test_dashboard_status_key(self) -> None:
        self.assertEqual(store.dashboard_status_key({"reachable": True, "locked": False}), "online")
        self.assertEqual(store.dashboard_status_key({"reachable": True, "locked": True}), "locked")
        self.assertEqual(store.dashboard_status_key({"reachable": False}), "offline")
        self.assertEqual(
            store.dashboard_status_key({"reachable": False, "connection_error": "bad clock"}),
            "cant_control",
        )
        self.assertEqual(
            store.dashboard_status_key({"reachable": False, "agent_not_running": True}),
            "not_signed_in",
        )

    def test_record_poll_inspect_coalesces_same_status(self) -> None:
        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1", locked=False))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            initial_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1", locked=False, accumulated_seconds=100),
        )
        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1", locked=False, accumulated_seconds=200),
        )

        pcs = store.get_tracked_ips()
        self.assertEqual(pcs["10.0.0.1"]["accumulated_seconds"], 200)
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], initial_scans
            )

    def test_record_poll_inspect_updates_hostname_column(self) -> None:
        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1", hostname="OldName"))

        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1", hostname="NewName", locked=False),
        )

        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            hostname = conn.execute("SELECT hostname FROM scan_pcs").fetchone()[0]
        self.assertEqual(hostname, "NewName")
        renamed_pc = store.get_scan_pc_by_hostname("newname")
        assert renamed_pc is not None
        self.assertEqual(renamed_pc["ip"], "10.0.0.1")

    def test_record_poll_inspect_inserts_on_status_change(self) -> None:
        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1", locked=False))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            initial_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1", locked=True))

        pcs = store.get_tracked_ips()
        self.assertTrue(pcs["10.0.0.1"]["locked"])
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], initial_scans + 1
            )
            poll_rows = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE network_label = ?",
                (store.POLL_NETWORK_LABEL,),
            ).fetchone()[0]
            self.assertEqual(poll_rows, initial_scans + 1)

    def test_record_poll_inspect_tracks_connection_failure(self) -> None:
        store.record_poll_inspect("10.0.0.1", _sample_pc_info(ip="10.0.0.1"))
        store.record_poll_inspect(
            "10.0.0.1",
            {
                "hostname": "KidPC",
                "reachable": False,
                "connection_error": "Cannot reach agent",
            },
        )
        pcs = store.get_tracked_ips()
        self.assertFalse(pcs["10.0.0.1"]["reachable"])
        self.assertIn("connection_error", pcs["10.0.0.1"])

    def test_prune_stale_tracked_ips_removes_orphan_scans(self) -> None:
        store.record_poll_inspect(
            "10.0.0.1",
            _sample_pc_info(ip="10.0.0.1"),
            when=datetime.now().astimezone() - timedelta(hours=13),
        )
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)

        store.prune_stale_tracked_ips(max_age_hours=12)

        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_pcs").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()

"""Tests for web panel snapshot persistence."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db
from kid_pc_monitor import snapshot_store as store


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
        "bed_time": "21:00",
        "wake_time": "07:00",
        "manual_lock_active": False,
        "enforcement_active": False,
        "enforcement_reason": None,
        "access_status": "Unlocked",
        "cumulative_extension_seconds": 0,
        "accumulated_seconds": 1800,
        "effective_limit_minutes": 120.0,
        "time_remaining": "90 minutes",
        "reachable": True,
    }
    base.update(overrides)
    return base


class SnapshotStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", self.db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def _insert_row(
        self,
        *,
        username: str,
        hostname: str,
        ip: str,
        snapshot_date: str,
        recorded_at: str,
        payload: dict,
    ) -> None:
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots
                    (username, hostname, ip, snapshot_date, recorded_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, hostname, ip, snapshot_date, recorded_at, json.dumps(payload)),
            )
            conn.commit()

    def test_save_snapshot_skips_unreachable(self) -> None:
        store.save_snapshot(_sample_pc_info(reachable=False))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 0)

    def test_save_snapshot_skips_missing_user(self) -> None:
        store.save_snapshot(_sample_pc_info(current_user=None))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 0)

    def test_same_day_replace(self) -> None:
        store.save_snapshot(_sample_pc_info(accumulated_seconds=100))
        store.save_snapshot(_sample_pc_info(accumulated_seconds=200))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            rows = conn.execute("SELECT payload_json FROM snapshots").fetchall()
        self.assertEqual(len(rows), 1)
        payload = json.loads(rows[0][0])
        self.assertEqual(payload["accumulated_seconds"], 200)

    def test_same_user_two_hostnames(self) -> None:
        store.save_snapshot(_sample_pc_info(hostname="PC-A"))
        store.save_snapshot(_sample_pc_info(hostname="PC-B"))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 2)

    def test_same_hostname_two_users(self) -> None:
        store.save_snapshot(_sample_pc_info(current_user="alice"))
        store.save_snapshot(_sample_pc_info(current_user="bob"))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 2)

    def test_get_latest_snapshot_for_pc_by_hostname(self) -> None:
        today = date.today().isoformat()
        self._insert_row(
            username="alice",
            hostname="KidPC",
            ip="10.0.0.1",
            snapshot_date=today,
            recorded_at="2026-06-01T10:00:00",
            payload=_sample_pc_info(accumulated_seconds=100),
        )
        self._insert_row(
            username="bob",
            hostname="KidPC",
            ip="10.0.0.1",
            snapshot_date=today,
            recorded_at="2026-06-01T12:00:00",
            payload=_sample_pc_info(current_user="bob", accumulated_seconds=999),
        )
        result = store.get_latest_snapshot_for_pc(hostname="KidPC")
        assert result is not None
        _recorded_at, payload = result
        self.assertEqual(_recorded_at, "2026-06-01T12:00:00")
        self.assertEqual(payload["accumulated_seconds"], 999)

    def test_get_latest_snapshot_for_pc_by_ip(self) -> None:
        today = date.today().isoformat()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.55",
            snapshot_date=today,
            recorded_at="2026-06-01T09:00:00",
            payload=_sample_pc_info(ip="192.168.1.55"),
        )
        result = store.get_latest_snapshot_for_pc(ip="192.168.1.55")
        assert result is not None
        self.assertEqual(result[1]["hostname"], "KidPC")

    def test_get_latest_snapshot_falls_back_to_ip(self) -> None:
        today = date.today().isoformat()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.10",
            snapshot_date=today,
            recorded_at="2026-06-01T09:00:00",
            payload=_sample_pc_info(ip="192.168.1.10"),
        )
        result = store.get_latest_snapshot_for_pc(hostname="PC at 192.168.1.10", ip="192.168.1.10")
        assert result is not None
        self.assertEqual(result[1]["hostname"], "KidPC")

    def test_get_latest_reachable_finds_prior_ip_by_hostname(self) -> None:
        today = date.today().isoformat()
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.50",
            snapshot_date=yesterday,
            recorded_at="2026-06-05T14:16:54",
            payload=_sample_pc_info(
                hostname="KidPC",
                ip="192.168.1.50",
                accumulated_seconds=12396,
            ),
        )
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.55",
            snapshot_date=today,
            recorded_at="2026-06-06T14:30:26",
            payload=_sample_pc_info(
                hostname="KidPC",
                ip="192.168.1.55",
                reachable=False,
                connection_error="timed out",
            ),
        )
        self.assertIsNone(store.get_latest_snapshot_for_pc(ip="192.168.1.55", reachable_only=True))
        result = store.get_latest_snapshot_for_pc(hostname="KidPC", reachable_only=True)
        assert result is not None
        self.assertEqual(result[1]["accumulated_seconds"], 12396)
        self.assertEqual(result[1]["ip"], "192.168.1.50")

    def test_get_latest_panel_snapshot_uses_unreachable_with_panel_data(self) -> None:
        today = date.today().isoformat()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.55",
            snapshot_date=today,
            recorded_at="2026-06-06T14:40:09",
            payload=_sample_pc_info(
                ip="192.168.1.55",
                reachable=False,
                connection_error="timed out",
                locked=True,
                status="LOCKED",
                accumulated_seconds=28801,
            ),
        )
        result = store.get_latest_panel_snapshot_for_pc(ip="192.168.1.55")
        assert result is not None
        self.assertEqual(result[1]["accumulated_seconds"], 28801)
        self.assertFalse(result[1]["reachable"])

    def test_get_latest_panel_snapshot_prefers_reachable(self) -> None:
        today = date.today().isoformat()
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.10",
            snapshot_date=yesterday,
            recorded_at="2026-06-01T10:00:00",
            payload=_sample_pc_info(accumulated_seconds=500),
        )
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.10",
            snapshot_date=today,
            recorded_at="2026-06-01T12:00:00",
            payload=_sample_pc_info(
                reachable=False,
                connection_error="timed out",
                status="LOCKED",
                accumulated_seconds=28801,
            ),
        )
        result = store.get_latest_panel_snapshot_for_pc(ip="192.168.1.10")
        assert result is not None
        self.assertEqual(result[1]["accumulated_seconds"], 500)

    def test_get_latest_reachable_snapshot_skips_errors(self) -> None:
        today = date.today().isoformat()
        self._insert_row(
            username="",
            hostname="KidPC",
            ip="192.168.1.10",
            snapshot_date=today,
            recorded_at="2026-06-01T12:00:00",
            payload=_sample_pc_info(reachable=False, connection_error="bad clock"),
        )
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="192.168.1.10",
            snapshot_date=today,
            recorded_at="2026-06-01T10:00:00",
            payload=_sample_pc_info(accumulated_seconds=500),
        )
        result = store.get_latest_snapshot_for_pc(ip="192.168.1.10", reachable_only=True)
        assert result is not None
        self.assertEqual(result[1]["accumulated_seconds"], 500)

    def test_usage_history_fills_seven_days(self) -> None:
        today = date.today()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="10.0.0.1",
            snapshot_date=today.isoformat(),
            recorded_at=f"{today.isoformat()}T12:00:00",
            payload=_sample_pc_info(accumulated_seconds=500),
        )
        groups = store.get_usage_history_for_user("child", days=7)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["hostname"], "KidPC")
        self.assertEqual(len(groups[0]["days"]), 7)
        self.assertFalse(groups[0]["days"][-1].get("no_data"))
        self.assertEqual(groups[0]["days"][-1]["accumulated_seconds"], 500)
        self.assertTrue(groups[0]["days"][0].get("no_data"))

    def test_usage_history_groups_multiple_pcs(self) -> None:
        today = date.today().isoformat()
        self._insert_row(
            username="child",
            hostname="PC-A",
            ip="10.0.0.1",
            snapshot_date=today,
            recorded_at=f"{today}T10:00:00",
            payload=_sample_pc_info(hostname="PC-A"),
        )
        self._insert_row(
            username="child",
            hostname="PC-B",
            ip="10.0.0.2",
            snapshot_date=today,
            recorded_at=f"{today}T10:00:00",
            payload=_sample_pc_info(hostname="PC-B"),
        )
        groups = store.get_usage_history_for_user("child", days=7)
        self.assertEqual([g["hostname"] for g in groups], ["PC-A", "PC-B"])

    def test_trim_deletes_old_rows(self) -> None:
        old_date = (date.today() - timedelta(days=10)).isoformat()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="10.0.0.1",
            snapshot_date=old_date,
            recorded_at=f"{old_date}T10:00:00",
            payload=_sample_pc_info(),
        )
        store.maybe_trim_old_rows()
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
            last_trim = conn.execute(
                "SELECT value FROM panel_meta WHERE key = ?",
                (store.META_LAST_TRIM_AT,),
            ).fetchone()
        self.assertEqual(count, 0)
        self.assertIsNotNone(last_trim)

    def test_trim_skipped_within_interval(self) -> None:
        old_date = (date.today() - timedelta(days=10)).isoformat()
        self._insert_row(
            username="child",
            hostname="KidPC",
            ip="10.0.0.1",
            snapshot_date=old_date,
            recorded_at=f"{old_date}T10:00:00",
            payload=_sample_pc_info(),
        )
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            panel_db.set_meta(
                conn, store.META_LAST_TRIM_AT, datetime.now().astimezone().isoformat()
            )
            conn.commit()
        store.maybe_trim_old_rows()
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 1)

    def test_save_poll_snapshot_skips_unreachable(self) -> None:
        store.save_poll_snapshot(
            _sample_pc_info(reachable=False, connection_error="offline", current_user=None)
        )
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 0)

    def test_unreachable_poll_does_not_overwrite_reachable_snapshot(self) -> None:
        store.save_snapshot(_sample_pc_info(accumulated_seconds=1800))
        store.save_poll_snapshot(
            _sample_pc_info(reachable=False, connection_error="offline", accumulated_seconds=0)
        )
        result = store.get_latest_snapshot_for_pc(ip="192.168.1.10", reachable_only=True)
        assert result is not None
        self.assertEqual(result[1]["accumulated_seconds"], 1800)

    def test_save_poll_snapshot_stores_missing_user(self) -> None:
        store.save_poll_snapshot(_sample_pc_info(current_user=None))
        with sqlite3.connect(self.db_path) as conn:
            panel_db.ensure_schema(conn)
            count = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        self.assertEqual(count, 1)

    def test_get_dashboard_pcs_overlays_snapshot(self) -> None:
        from kid_pc_monitor import scan_store

        scan_store.save_scan(
            pcs={"192.168.1.10": {"hostname": "KidPC", "reachable": True, "locked": False}},
            scanned_at=datetime.now().astimezone(),
            network_label="lan",
            subnet="192.168.1.0/24",
        )
        store.save_poll_snapshot(_sample_pc_info(locked=True, accumulated_seconds=999))
        dashboard, last_poll_at = store.get_dashboard_pcs()
        self.assertIn("192.168.1.10", dashboard)
        self.assertTrue(dashboard["192.168.1.10"]["locked"])
        self.assertEqual(dashboard["192.168.1.10"]["accumulated_seconds"], 999)
        self.assertIsNotNone(last_poll_at)

    def test_get_dashboard_pcs_uses_scan_entry_when_unreachable(self) -> None:
        from kid_pc_monitor import scan_store

        scan_store.save_scan(
            pcs={
                "192.168.1.10": {
                    "hostname": "KidPC",
                    "reachable": True,
                    "locked": False,
                    "ip": "192.168.1.10",
                }
            },
            scanned_at=datetime.now().astimezone(),
            network_label="lan",
            subnet="192.168.1.0/24",
        )
        store.save_snapshot(_sample_pc_info(locked=True, accumulated_seconds=999))
        scan_store.record_poll_inspect(
            "192.168.1.10",
            {
                "hostname": "KidPC",
                "reachable": False,
                "locked": False,
                "ip": "192.168.1.10",
            },
        )
        dashboard, _last_poll_at = store.get_dashboard_pcs()
        self.assertFalse(dashboard["192.168.1.10"]["reachable"])
        self.assertFalse(dashboard["192.168.1.10"]["locked"])

    def test_get_dashboard_pcs_falls_back_to_scan_payload(self) -> None:
        from kid_pc_monitor import scan_store

        scan_store.save_scan(
            pcs={
                "192.168.1.10": {
                    "hostname": "KidPC",
                    "reachable": True,
                    "locked": False,
                    "ip": "192.168.1.10",
                }
            },
            scanned_at=datetime.now().astimezone(),
            network_label="lan",
            subnet="192.168.1.0/24",
        )
        dashboard, last_poll_at = store.get_dashboard_pcs()
        self.assertIn("192.168.1.10", dashboard)
        self.assertEqual(dashboard["192.168.1.10"]["hostname"], "KidPC")
        self.assertIsNone(last_poll_at)


if __name__ == "__main__":
    unittest.main()

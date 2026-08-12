"""Tests for web panel snapshot history integration."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db, scan_store, snapshot_store
from kid_pc_monitor import web_panel as wp
from kid_pc_monitor.panel_format import format_snapshot_recorded_at


def _sample_pc_info(**overrides: object) -> dict:
    base: dict = {
        "ip": "192.168.1.10",
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


class WebPanelHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self._tmpdir.name) / wp.AUTH_FILE
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patches = [
            mock.patch.object(wp, "_auth_path", return_value=self.auth_path),
            mock.patch.object(wp, "_auth_save_path", return_value=self.auth_path),
            mock.patch.object(panel_db, "_db_path_override", self.db_path),
        ]
        for patch in self._patches:
            patch.start()
        self.app = wp.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        for patch in self._patches:
            patch.stop()
        self._tmpdir.cleanup()

    def test_control_shows_snapshot_when_offline(self) -> None:
        scan_store.record_poll_inspect(
            "192.168.1.10",
            _sample_pc_info(ip="192.168.1.10", reachable=False),
        )
        snapshot_store.save_snapshot(_sample_pc_info(ip="192.168.1.10"))
        response = self.client.get("/control/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertIn("30 min", html)

    def test_control_shows_friendly_snapshot_time_for_today(self) -> None:
        now = datetime.now().astimezone()
        recorded = now.replace(hour=10, minute=30, second=0, microsecond=0)
        payload = _sample_pc_info(ip="192.168.1.10")
        scan_store.record_poll_inspect(
            "192.168.1.10",
            _sample_pc_info(ip="192.168.1.10", reachable=False),
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
                    "child",
                    "KidPC",
                    "192.168.1.10",
                    recorded.date().isoformat(),
                    recorded.isoformat(timespec="seconds"),
                    json.dumps(payload),
                ),
            )
            conn.commit()
        expected = format_snapshot_recorded_at(
            recorded.isoformat(timespec="seconds"),
            now=now,
        )
        response = self.client.get("/control/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn(expected, html)
        self.assertNotIn(recorded.isoformat(timespec="seconds"), html)

    def test_control_shows_unreachable_snapshot_with_panel_data(self) -> None:
        scan_store.record_poll_inspect(
            "192.168.1.55",
            {
                "hostname": "KidPC",
                "reachable": False,
                "ip": "192.168.1.55",
            },
        )
        today = datetime.now().astimezone().date().isoformat()
        payload = _sample_pc_info(
            ip="192.168.1.55",
            reachable=False,
            connection_error="timed out",
            locked=True,
            status="LOCKED",
            accumulated_seconds=28801,
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
                    "child",
                    "KidPC",
                    "192.168.1.55",
                    today,
                    datetime.now().astimezone().isoformat(timespec="seconds"),
                    json.dumps(payload),
                ),
            )
            conn.commit()
        response = self.client.get("/control/192.168.1.55")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertIn("8:00", html)
        self.assertNotIn("timed out", html)
        self.assertNotIn("offline or unreachable", html.lower())

    def test_control_shows_snapshot_when_ip_changed(self) -> None:
        scan_store.record_poll_inspect(
            "192.168.1.55",
            {
                "hostname": "KidPC",
                "reachable": False,
                "ip": "192.168.1.55",
            },
        )
        snapshot_store.save_snapshot(
            _sample_pc_info(
                hostname="KidPC",
                ip="192.168.1.50",
                accumulated_seconds=12396,
            )
        )
        response = self.client.get("/control/192.168.1.55")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertIn("3:27", html)
        self.assertNotIn("offline or unreachable", html.lower())

    def test_control_hostname_uses_latest_registry_ip(self) -> None:
        scan_store.record_poll_inspect(
            "192.168.1.50", _sample_pc_info(ip="192.168.1.50", hostname="KidPC")
        )
        scan_store.record_poll_inspect(
            "192.168.1.55", _sample_pc_info(ip="192.168.1.55", hostname="OtherPC")
        )
        scan_store.record_poll_inspect(
            "192.168.1.60", _sample_pc_info(ip="192.168.1.60", hostname="KidPC")
        )

        session = mock.Mock()
        session.hostname = "KidPC"
        session.pc_info = {
            "name": "KidPC",
            "status": "UNLOCKED",
            "current_user": "child",
            "daily_limit": 120,
            "manual_lock": False,
            "cumulative_extension": 0,
            "accumulated_seconds": 1800,
            "time_remaining": 90,
            "access_status": "Unlocked",
        }
        reverse = mock.Mock()
        reverse.session_for_ip.return_value = session

        with mock.patch.object(wp, "get_reverse_server", return_value=reverse):
            response = self.client.get("/control/KidPC")

        self.assertEqual(response.status_code, 200)
        reverse.session_for_ip.assert_called_with("192.168.1.60")
        html = response.get_data(as_text=True)
        self.assertIn('data-ip="192.168.1.60"', html)
        self.assertIn("KidPC", html)

    def test_control_hostname_without_registry_returns_404(self) -> None:
        response = self.client.get("/control/KidPC")

        self.assertEqual(response.status_code, 404)
        html = response.get_data(as_text=True)
        self.assertIn("No connected PC found for KidPC", html)
        self.assertIn("PCs appear here after the agent connects", html)

    def test_control_shows_snapshot_after_unreachable_registry(self) -> None:
        scan_store.record_poll_inspect("192.168.1.10", _sample_pc_info(ip="192.168.1.10"))
        snapshot_store.save_snapshot(_sample_pc_info(ip="192.168.1.10"))
        scan_store.record_poll_inspect(
            "192.168.1.10",
            {
                "hostname": "KidPC",
                "ip": "192.168.1.10",
                "reachable": False,
            },
        )
        response = self.client.get("/control/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertIn("30 min", html)
        self.assertNotIn("offline or unreachable", html.lower())

    def test_usage_page_renders_history(self) -> None:
        snapshot_store.save_snapshot(_sample_pc_info(current_user="child"))
        response = self.client.get("/usage/child")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Usage history", html)
        self.assertIn("KidPC", html)
        self.assertIn("30 min", html)

    def test_usage_page_multi_pc(self) -> None:
        snapshot_store.save_snapshot(
            _sample_pc_info(current_user="child", hostname="PC-A", ip="10.0.0.1")
        )
        snapshot_store.save_snapshot(
            _sample_pc_info(current_user="child", hostname="PC-B", ip="10.0.0.2")
        )
        response = self.client.get("/usage/child")
        html = response.get_data(as_text=True)
        self.assertIn("PC-A", html)
        self.assertIn("PC-B", html)


if __name__ == "__main__":
    unittest.main()

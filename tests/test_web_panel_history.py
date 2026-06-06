"""Tests for web panel snapshot history integration."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db, snapshot_store
from kid_pc_monitor import web_panel as wp


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
        snapshot_store.save_snapshot(_sample_pc_info(ip="192.168.1.10"))
        with mock.patch.object(wp, "inspect_pc", side_effect=ConnectionError("offline")):
            response = self.client.get("/control/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertIn("30 min", html)

    def test_control_shows_snapshot_when_ip_changed(self) -> None:
        from kid_pc_monitor import scan_store

        scan_store.save_scan(
            pcs={
                "192.168.1.55": {
                    "hostname": "KidPC",
                    "reachable": False,
                    "ip": "192.168.1.55",
                }
            },
            scanned_at=datetime.now().astimezone(),
            network_label="lan",
            subnet="192.168.1.0/24",
        )
        snapshot_store.save_snapshot(
            _sample_pc_info(
                hostname="KidPC",
                ip="192.168.1.50",
                accumulated_seconds=12396,
            )
        )
        unreachable = ConnectionError("Cannot reach agent at 192.168.1.55:9999: timed out")
        with mock.patch.object(wp, "inspect_pc", side_effect=unreachable):
            response = self.client.get("/control/192.168.1.55")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertIn("3:27", html)
        self.assertNotIn("offline or unreachable", html.lower())

    def test_control_shows_snapshot_after_unreachable_poll(self) -> None:
        from kid_pc_monitor import agent_poller, scan_store

        scan_store.save_scan(
            pcs={"192.168.1.10": _sample_pc_info(ip="192.168.1.10")},
            scanned_at=datetime.now().astimezone(),
            network_label="lan",
            subnet="192.168.1.0/24",
        )
        snapshot_store.save_snapshot(_sample_pc_info(ip="192.168.1.10"))
        unreachable = ConnectionError(
            "Cannot reach agent at 192.168.1.10:9999: [Errno 113] No route to host"
        )
        with mock.patch.object(agent_poller, "inspect_pc", side_effect=unreachable):
            agent_poller.poll_once()
        with mock.patch.object(wp, "inspect_pc", side_effect=unreachable):
            response = self.client.get("/control/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertIn("30 min", html)
        self.assertNotIn("offline or unreachable", html.lower())

    def test_scan_records_snapshot(self) -> None:
        discovered = {"192.168.1.10": {"hostname": "KidPC", "reachable": True}}
        with mock.patch.object(wp, "scan_for_servers", return_value=discovered):
            with mock.patch.object(wp, "inspect_pc", return_value=_sample_pc_info()):
                csrf = self.client.get("/").headers.get("Set-Cookie", "")
                self.assertTrue(csrf)
                response = self.client.post(
                    "/scan",
                    data={"subnet": "", "csrf_token": self._csrf_from_index()},
                )
        self.assertEqual(response.status_code, 302)
        result = snapshot_store.get_latest_snapshot_for_pc(hostname="KidPC")
        self.assertIsNotNone(result)

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

    def _csrf_from_index(self) -> str:
        response = self.client.get("/")
        import re

        html = response.get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        assert match is not None
        return match.group(1)


if __name__ == "__main__":
    unittest.main()

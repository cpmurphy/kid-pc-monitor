"""Tests for parent-friendly agent connection error messages."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor import panel_db, scan_store
from kid_pc_monitor import web_panel as wp
from kid_pc_monitor.remote_client import (
    connection_failure_fields,
    format_agent_connection_error,
    is_agent_not_running_error,
    is_offline_connection_error,
)


class FormatAgentConnectionErrorTests(unittest.TestCase):
    def test_stale_timestamp_from_protocol_error(self) -> None:
        exc = proto.ProtocolError(
            proto.STALE_TIMESTAMP,
            "timestamp outside allowed window",
        )
        message = format_agent_connection_error(exc)
        self.assertIn("clock is out of sync", message)
        self.assertIn("VM", message)

    def test_stale_timestamp_from_connection_error(self) -> None:
        exc = ConnectionError(
            "Cannot reach agent at 192.168.1.20:9999: timestamp outside allowed window"
        )
        message = format_agent_connection_error(exc)
        self.assertIn("clock is out of sync", message)

    def test_shared_secret_missing(self) -> None:
        exc = ConnectionError(
            "Cannot reach agent at 192.168.1.1:9999: "
            "No shared secret is configured. Re-run the installer to set the "
            "panel/agent shared secret on this machine."
        )
        message = format_agent_connection_error(exc)
        self.assertIn("No shared secret is configured", message)

    def test_connection_failure_fields(self) -> None:
        exc = ConnectionError(
            "Cannot reach agent at 192.168.1.20:9999: timestamp outside allowed window"
        )
        fields = connection_failure_fields(exc)
        self.assertFalse(fields["reachable"])
        self.assertIn("clock is out of sync", fields["connection_error"])

    def test_errno_113_is_offline(self) -> None:
        os_exc = OSError(113, "No route to host")
        exc = ConnectionError(
            "Cannot reach agent at 192.168.1.10:9999: [Errno 113] No route to host"
        )
        exc.__cause__ = os_exc
        self.assertTrue(is_offline_connection_error(exc))
        fields = connection_failure_fields(exc)
        self.assertFalse(fields["reachable"])
        self.assertNotIn("connection_error", fields)

    def test_connection_refused_is_agent_not_running(self) -> None:
        os_exc = ConnectionRefusedError(111, "Connection refused")
        exc = ConnectionError(
            "Cannot reach agent at 192.168.1.10:9999: [Errno 111] Connection refused"
        )
        exc.__cause__ = os_exc
        self.assertTrue(is_agent_not_running_error(exc))
        fields = connection_failure_fields(exc)
        self.assertFalse(fields["reachable"])
        self.assertTrue(fields["agent_not_running"])
        self.assertNotIn("connection_error", fields)

    def test_windows_connection_refused_is_agent_not_running(self) -> None:
        exc = ConnectionError(
            "Cannot reach agent at 192.168.1.10:9999: "
            "[WinError 10061] No connection could be made because the target machine "
            "actively refused it"
        )
        self.assertTrue(is_agent_not_running_error(exc))

    def test_stale_clock_is_not_agent_not_running(self) -> None:
        exc = ConnectionError(
            "Cannot reach agent at 192.168.1.20:9999: timestamp outside allowed window"
        )
        self.assertFalse(is_agent_not_running_error(exc))


class WebPanelConnectionErrorTests(unittest.TestCase):
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

    def test_registry_shows_cant_control_for_stale_clock(self) -> None:
        stale = ConnectionError(
            "Cannot reach agent at 192.168.1.20:9999: timestamp outside allowed window"
        )
        fields = connection_failure_fields(stale)
        scan_store.record_poll_inspect(
            "192.168.1.20",
            {"hostname": "KidPC", "ip": "192.168.1.20", **fields},
        )

        home = self.client.get("/")
        html = home.get_data(as_text=True)
        self.assertIn("CAN'T CONTROL", html)

    def test_registry_shows_not_connected_for_no_route_to_host(self) -> None:
        os_exc = OSError(113, "No route to host")
        unreachable = ConnectionError(
            "Cannot reach agent at 192.168.1.20:9999: [Errno 113] No route to host"
        )
        unreachable.__cause__ = os_exc
        fields = connection_failure_fields(unreachable)
        scan_store.record_poll_inspect(
            "192.168.1.20",
            {"hostname": "KidPC", "ip": "192.168.1.20", **fields},
        )

        home = self.client.get("/")
        html = home.get_data(as_text=True)
        self.assertIn("NOT CONNECTED", html)
        self.assertNotIn("CAN'T CONTROL", html)

    def test_registry_shows_not_connected_for_refused_connection(self) -> None:
        os_exc = ConnectionRefusedError(111, "Connection refused")
        refused = ConnectionError(
            "Cannot reach agent at 192.168.1.20:9999: [Errno 111] Connection refused"
        )
        refused.__cause__ = os_exc
        fields = connection_failure_fields(refused)
        scan_store.record_poll_inspect(
            "192.168.1.20",
            {"hostname": "KidPC", "ip": "192.168.1.20", **fields},
        )

        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("NOT CONNECTED", html)
        self.assertNotIn("CAN'T CONTROL", html)

    def test_control_page_shows_connection_error(self) -> None:
        stale = ConnectionError(
            "Cannot reach agent at 192.168.1.20:9999: timestamp outside allowed window"
        )
        fields = connection_failure_fields(stale)
        scan_store.record_poll_inspect(
            "192.168.1.20",
            {"hostname": "KidPC", "ip": "192.168.1.20", **fields},
        )
        response = self.client.get("/control/192.168.1.20")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("clock is out of sync", html)


if __name__ == "__main__":
    unittest.main()

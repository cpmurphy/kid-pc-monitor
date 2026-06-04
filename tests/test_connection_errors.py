"""Tests for parent-friendly agent connection error messages."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from werkzeug.security import generate_password_hash

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor import panel_db, scan_store
from kid_pc_monitor import web_panel as wp
from kid_pc_monitor.remote_client import (
    connection_failure_fields,
    format_agent_connection_error,
    request_text,
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

    def test_stale_timestamp_from_inspect_connection_error(self) -> None:
        exc = ConnectionError(
            "Cannot reach agent at 192.168.123.6:9999: timestamp outside allowed window"
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
            "Cannot reach agent at 192.168.123.6:9999: timestamp outside allowed window"
        )
        fields = connection_failure_fields(exc)
        self.assertFalse(fields["reachable"])
        self.assertIn("clock is out of sync", fields["connection_error"])


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

    def _write_auth(self, password: str = "supersecret1") -> None:
        auth = {
            "secret_key": "c" * 32,
            "password_hash": generate_password_hash(password, method="scrypt"),
        }
        self.auth_path.write_text(json.dumps(auth), encoding="utf-8")

    def _csrf_from_html(self, html: str) -> str:
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        assert match is not None, "csrf token not found in page"
        return match.group(1)

    def _login(self) -> None:
        self._write_auth()
        csrf = self._csrf_from_html(self.client.get("/login").get_data(as_text=True))
        self.client.post("/login", data={"password": "supersecret1", "csrf_token": csrf})

    def test_scan_records_connection_error_for_stale_clock(self) -> None:
        self._login()
        csrf = self._csrf_from_html(self.client.get("/").get_data(as_text=True))
        stale = ConnectionError(
            "Cannot reach agent at 192.168.123.6:9999: timestamp outside allowed window"
        )
        discovered = {
            "192.168.123.6": {
                "hostname": "win11-vm-1",
                "status": "online",
            }
        }
        with (
            mock.patch.object(wp, "scan_for_servers", return_value=discovered),
            mock.patch.object(wp, "inspect_pc", side_effect=stale),
        ):
            response = self.client.post("/scan", data={"csrf_token": csrf, "subnet": ""})
        self.assertEqual(response.status_code, 302)

        pcs = scan_store.get_discovered_pcs()
        entry = pcs["192.168.123.6"]
        self.assertFalse(entry["reachable"])
        self.assertIn("clock is out of sync", entry["connection_error"])

        home = self.client.get("/")
        html = home.get_data(as_text=True)
        self.assertIn("CAN'T CONTROL", html)

    def test_control_page_shows_connection_error(self) -> None:
        self._login()
        stale = ConnectionError(
            "Cannot reach agent at 192.168.123.6:9999: timestamp outside allowed window"
        )
        with mock.patch.object(wp, "inspect_pc", side_effect=stale):
            response = self.client.get("/control/192.168.123.6")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("clock is out of sync", html)

    def test_request_text_formats_stale_timestamp(self) -> None:
        with mock.patch(
            "kid_pc_monitor.remote_client.send_request",
            side_effect=proto.ProtocolError(
                proto.STALE_TIMESTAMP,
                "timestamp outside allowed window",
            ),
        ):
            ok, message = request_text("192.168.123.6", "lock")
        self.assertFalse(ok)
        self.assertIn("clock is out of sync", message)


if __name__ == "__main__":
    unittest.main()

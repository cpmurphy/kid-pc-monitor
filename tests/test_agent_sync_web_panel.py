"""Tests for web-panel reverse agent polling endpoints."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor import agent_sync_store, panel_db
from kid_pc_monitor import web_panel as wp
from kid_pc_monitor.agent_protocol import Node

SECRET = "test-shared-secret"
HOSTNAME = "KidPC"


def _settings_frame() -> str:
    content = [
        Node("status", ["ok"]),
        Node(
            "settings",
            children=[
                Node("name", [HOSTNAME]),
                Node("status", ["UNLOCKED"]),
                Node("current_user", ["child"]),
                Node("daily_limit", [120]),
                Node("bed_time", ["21:00"]),
                Node("manual_lock", [False]),
                Node("wake_time", ["07:00"]),
                Node("cumulative_extension", [0]),
                Node("accumulated_seconds", [60]),
                Node("time_remaining", [119]),
                Node("enforcement_active", [False]),
                Node("enforcement_reason", [None]),
                Node("access_status", ["Unlocked"]),
            ],
        ),
    ]
    return proto.sign_response(content, secret=SECRET, hostname=HOSTNAME)


class AgentSyncWebPanelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self._tmpdir.name) / wp.AUTH_FILE
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patches = [
            mock.patch.object(wp, "_auth_path", return_value=self.auth_path),
            mock.patch.object(wp, "_auth_save_path", return_value=self.auth_path),
            mock.patch.object(panel_db, "_db_path_override", self.db_path),
            mock.patch.object(wp.shared_secret, "require_shared_secret", return_value=SECRET),
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

    def _csrf_from_index(self) -> str:
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        match = re.search(r'name="csrf-token" content="([^"]+)"', html)
        assert match is not None
        return match.group(1)

    def test_discover_marker(self) -> None:
        response = self.client.get("/agent/v1/discover")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["service"], "kid-pc-monitor-panel")

    def test_poll_records_status_and_returns_queued_command(self) -> None:
        command_id = agent_sync_store.enqueue_command(
            hostname=HOSTNAME,
            action_name="lock",
            request_fields={"action": "lock", "var": None, "val": None, "tail": None},
        )

        response = self.client.post(
            "/agent/v1/poll",
            json={"status": _settings_frame(), "results": []},
            environ_base={"REMOTE_ADDR": "192.168.1.10"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["commands"][0]["id"], command_id)
        req = proto.parse_request(
            payload["commands"][0]["request"], secret=SECRET, hostname=HOSTNAME
        )
        self.assertEqual(req.action, "lock")
        agent = agent_sync_store.recent_agent_for_ip("192.168.1.10")
        assert agent is not None
        self.assertEqual(agent["hostname"], HOSTNAME)

    def test_poll_result_for_wrong_hostname_does_not_complete_command(self) -> None:
        command_id = agent_sync_store.enqueue_command(
            hostname="OtherPC",
            action_name="lock",
            request_fields={"action": "lock", "var": None, "val": None, "tail": None},
        )
        response_frame = proto.sign_response(
            proto.ok_content("locked"), secret=SECRET, hostname=HOSTNAME
        )

        response = self.client.post(
            "/agent/v1/poll",
            json={
                "status": _settings_frame(),
                "results": [{"command_id": command_id, "response": response_frame}],
            },
            environ_base={"REMOTE_ADDR": "192.168.1.10"},
        )

        self.assertEqual(response.status_code, 200)
        status = agent_sync_store.command_status(command_id)
        assert status is not None
        self.assertTrue(status["pending"])

    def test_action_queues_for_recent_reverse_agent(self) -> None:
        agent_sync_store.record_agent_poll(
            HOSTNAME,
            "192.168.1.10",
            {"hostname": HOSTNAME, "status": "UNLOCKED", "reachable": True},
        )
        csrf = self._csrf_from_index()

        with mock.patch.object(wp, "perform_action") as perform_mock:
            response = self.client.post(
                "/action",
                json={"ip": "192.168.1.10", "action": "lock"},
                headers={"X-CSRF-Token": csrf},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["pending"])
        self.assertIsInstance(payload["command_id"], int)
        perform_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

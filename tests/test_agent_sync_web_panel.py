"""Tests for reverse TCP agent sessions via the web panel."""

from __future__ import annotations

import re
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor import agent_sync_store, panel_db
from kid_pc_monitor import panel_reverse_server as reverse
from kid_pc_monitor import web_panel as wp
from kid_pc_monitor.agent_protocol import Node

SECRET = "test-shared-secret"
HOSTNAME = "KidPC"


def _settings_nodes() -> list[Node]:
    return [
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


def _agent_loop(sock: socket.socket, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            sock.settimeout(0.5)
            try:
                body = proto.read_frame(sock)
            except TimeoutError:
                continue
            except (OSError, proto.ProtocolError, proto.ConnectionClosedBeforeFrame):
                return
            req = proto.parse_request(body, secret=SECRET, hostname=HOSTNAME)
            if req.action == "get" and req.var == "settings":
                content = _settings_nodes()
            elif req.action == "lock":
                content = proto.ok_content("locked")
            elif req.action == "get_logs":
                content = [
                    Node("status", ["ok"]),
                    Node(
                        "logs",
                        children=[Node("truncated", [False]), Node("line", ["hello"])],
                    ),
                ]
            else:
                content = proto.ok_content("ok")
            response = proto.sign_response(
                content,
                secret=SECRET,
                hostname=HOSTNAME,
                req_id=req.id,
            )
            sock.sendall(proto.encode_frame(response))
    finally:
        try:
            sock.close()
        except OSError:
            pass


class ReverseTcpWebPanelTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self._tmpdir.name) / wp.AUTH_FILE
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self.reverse_port = sock.getsockname()[1]
        sock.close()
        self._patches = [
            mock.patch.object(wp, "_auth_path", return_value=self.auth_path),
            mock.patch.object(wp, "_auth_save_path", return_value=self.auth_path),
            mock.patch.object(panel_db, "_db_path_override", self.db_path),
            mock.patch.object(reverse.shared_secret, "require_shared_secret", return_value=SECRET),
        ]
        for patch in self._patches:
            patch.start()
        self.app = wp.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self._stop = threading.Event()
        self._agent_thread: threading.Thread | None = None
        self.server = reverse.start_panel_reverse_server(
            host="127.0.0.1",
            port=self.reverse_port,
            on_status=wp._record_reverse_pc_info,
            on_disconnect=wp._record_reverse_disconnect,
        )
        time.sleep(0.15)

    def tearDown(self) -> None:
        self._stop.set()
        if self._agent_thread is not None:
            self._agent_thread.join(timeout=2)
        reverse.stop_panel_reverse_server()
        for patch in self._patches:
            patch.stop()
        self._tmpdir.cleanup()

    def _connect_agent(self) -> None:
        from kid_pc_monitor import scan_store

        sock = socket.create_connection(("127.0.0.1", self.reverse_port), timeout=2)
        self._agent_thread = threading.Thread(
            target=_agent_loop, args=(sock, self._stop), daemon=True
        )
        self._agent_thread.start()
        # The session is registered before the status callback persists it, so wait for
        # the recorded state too -- otherwise the dashboard row may not exist yet.
        deadline = time.time() + 3
        while time.time() < deadline:
            if (
                self.server.session_for_hostname(HOSTNAME) is not None
                and agent_sync_store.recent_agent_for_ip("127.0.0.1") is not None
                and "127.0.0.1" in scan_store.get_tracked_ips()
            ):
                return
            time.sleep(0.05)
        self.fail("Reverse session was not registered")

    def _csrf_from_index(self) -> str:
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        match = re.search(r'name="csrf-token" content="([^"]+)"', html)
        assert match is not None
        return match.group(1)

    def test_discover_includes_reverse_port(self) -> None:
        with mock.patch.object(wp, "reverse_listen_port", return_value=9998):
            response = self.client.get("/agent/v1/discover")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["service"], "kid-pc-monitor-panel")
        self.assertEqual(payload["reverse_port"], 9998)

    def test_reverse_identify_records_status(self) -> None:
        self._connect_agent()
        agent = agent_sync_store.recent_agent_for_ip("127.0.0.1")
        assert agent is not None
        self.assertEqual(agent["hostname"], HOSTNAME)

    def test_disconnect_marks_agent_offline(self) -> None:
        from kid_pc_monitor import scan_store, snapshot_store

        self._connect_agent()
        self.assertIsNotNone(agent_sync_store.recent_agent_for_ip("127.0.0.1"))
        dashboard, _ = snapshot_store.get_dashboard_pcs()
        self.assertTrue(dashboard["127.0.0.1"]["reachable"])

        session = self.server.session_for_hostname(HOSTNAME)
        assert session is not None
        session.close()

        deadline = time.time() + 3
        while time.time() < deadline:
            if (
                self.server.session_for_hostname(HOSTNAME) is None
                and agent_sync_store.recent_agent_for_ip("127.0.0.1") is None
            ):
                break
            time.sleep(0.05)
        else:
            self.fail("Reverse session did not unregister after close")

        tracked = scan_store.get_tracked_ips()
        self.assertFalse(tracked["127.0.0.1"].get("reachable", True))
        dashboard, _ = snapshot_store.get_dashboard_pcs()
        self.assertFalse(dashboard["127.0.0.1"]["reachable"])

        response = self.client.get("/control/127.0.0.1")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("recorded snapshot", html.lower())
        self.assertNotIn("Quick Actions", html)

    def test_action_uses_live_reverse_session(self) -> None:
        self._connect_agent()
        csrf = self._csrf_from_index()

        response = self.client.post(
            "/action",
            json={"ip": "127.0.0.1", "action": "lock"},
            headers={"X-CSRF-Token": csrf},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"], payload)
        self.assertNotIn("command_id", payload)


if __name__ == "__main__":
    unittest.main()

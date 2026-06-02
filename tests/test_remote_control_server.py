"""Tests for the agent TCP remote control server."""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.pc_time_control import PCTimeControl
from kid_pc_monitor.remote_control_server import RemoteControlServer
from test_pc_time_control import FakeHostPlatform

SECRET = "test-shared-secret"


class ServerIntegrationTests(unittest.TestCase):
    """Drive RemoteControlServer.handle_client over a socket pair."""

    def _serve(self, control: PCTimeControl) -> tuple[socket.socket, threading.Thread]:
        server = RemoteControlServer()
        server.pc_control = control
        server.running = True
        server._shared_secret = SECRET
        client_end, server_end = socket.socketpair()
        thread = threading.Thread(
            target=server.handle_client, args=(server_end, ("test", 0), 0), daemon=True
        )
        thread.start()
        return client_end, thread

    def test_structured_request_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=FakeHostPlatform(hostname="kid-pc"),
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            client_end, thread = self._serve(control)
            try:
                # Discovery: unnamed read learns and authenticates the hostname.
                client_end.sendall(
                    proto.encode_frame(proto.build_request("get", secret=SECRET, var="name"))
                )
                resp = proto.parse_response(proto.read_frame(client_end), secret=SECRET)
                self.assertEqual(resp.result, "kid-pc")
                self.assertEqual(resp.name, "kid-pc")

                # A named write, signed with the per-agent key.
                client_end.sendall(
                    proto.encode_frame(
                        proto.build_request(
                            "set", secret=SECRET, var="daily_limit", val=75, name="kid-pc"
                        )
                    )
                )
                resp = proto.parse_response(
                    proto.read_frame(client_end), secret=SECRET, expected_name="kid-pc"
                )
                self.assertTrue(resp.ok)
                self.assertEqual(control.daily.allowance, 75)
            finally:
                client_end.close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

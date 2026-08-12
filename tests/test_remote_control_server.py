"""Tests for agent request handling (reverse-session entry point)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.pc_time_control import PCTimeControl
from kid_pc_monitor.remote_control_server import handle_request
from test_pc_time_control import FakeHostPlatform

SECRET = "test-shared-secret"


class HandleRequestTests(unittest.TestCase):
    """Drive handle_request without a listening TCP server."""

    def test_structured_request_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=FakeHostPlatform(hostname="kid-pc"),
                data_directory=Path(tmp),
                start_background_threads=False,
            )

            # Discovery: unnamed read learns and authenticates the hostname.
            resp_body = handle_request(
                control,
                proto.build_request("get", secret=SECRET, var="name"),
                secret=SECRET,
            )
            resp = proto.parse_response(resp_body, secret=SECRET)
            self.assertEqual(resp.result, "kid-pc")
            self.assertEqual(resp.name, "kid-pc")

            # A named write, signed with the per-agent key.
            resp_body = handle_request(
                control,
                proto.build_request("set", secret=SECRET, var="daily_limit", val=75, name="kid-pc"),
                secret=SECRET,
            )
            resp = proto.parse_response(resp_body, secret=SECRET, expected_name="kid-pc")
            self.assertTrue(resp.ok)
            self.assertEqual(control.daily.allowance, 75)

    def test_protocol_error_becomes_signed_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=FakeHostPlatform(hostname="kid-pc"),
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            # Write without a name → authentication / protocol failure path.
            resp_body = handle_request(
                control,
                proto.build_request("lock", secret=SECRET),
                secret=SECRET,
            )
            resp = proto.parse_response(resp_body, secret=SECRET)
            self.assertFalse(resp.ok)
            self.assertEqual(resp.name, "kid-pc")


if __name__ == "__main__":
    unittest.main()

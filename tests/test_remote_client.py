"""Tests for remote_client helpers (reverse-path formatting and protocol mapping)."""

from __future__ import annotations

import io
import unittest

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.remote_client import (
    _legacy_access_status,
    _print_frame,
    action_request_fields,
    connection_failure_fields,
    format_agent_connection_error,
    is_agent_not_running_error,
    is_offline_connection_error,
    settings_to_pc_info,
)


class RemoteClientTests(unittest.TestCase):
    def test_legacy_access_status_fallback(self) -> None:
        self.assertEqual(_legacy_access_status("UNLOCKED", False), "Unlocked")
        self.assertEqual(_legacy_access_status("LOCKED", False), "Screen locked")
        self.assertEqual(_legacy_access_status("UNLOCKED", True), "Locked — manual lock")

    def test_print_frame_prefixes_lines(self) -> None:
        out = io.StringIO()
        _print_frame(">", "v 2\naction get", out=out)
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "> 14")
        self.assertEqual(lines[1], "> v 2")
        self.assertEqual(lines[2], "> action get")


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


class ActionRequestFieldsTests(unittest.TestCase):
    def test_lock_and_extend(self) -> None:
        self.assertEqual(action_request_fields("lock"), ("lock", None, None, None))
        self.assertEqual(
            action_request_fields("extend_time", {"minutes": 15}),
            ("extend", None, 15, None),
        )

    def test_settings_actions(self) -> None:
        self.assertEqual(
            action_request_fields("set_daily_limit", {"minutes": 90}),
            ("set", "daily_limit", 90, None),
        )
        self.assertEqual(
            action_request_fields("set_daily_limit", {"minutes": ""}),
            ("clear", "daily_limit", None, None),
        )
        self.assertEqual(
            action_request_fields("set_bed_time", {"time": "21:00"}),
            ("set", "bed_time", "21:00", None),
        )

    def test_get_logs_tail(self) -> None:
        action, var, val, tail = action_request_fields("get_logs", {"tail": 50})
        self.assertEqual(action, "get_logs")
        self.assertIsNone(var)
        self.assertIsNone(val)
        self.assertEqual(tail, 50)

    def test_unknown_action_raises(self) -> None:
        with self.assertRaises(KeyError):
            action_request_fields("not_a_real_action")


class SettingsToPcInfoTests(unittest.TestCase):
    def test_basic_conversion(self) -> None:
        info = settings_to_pc_info(
            {
                "name": "KidPC",
                "status": "UNLOCKED",
                "current_user": "child",
                "daily_limit": 120,
                "bed_time": "21:00",
                "wake_time": "07:00",
                "manual_lock": False,
                "cumulative_extension": 0,
                "accumulated_seconds": 1800,
                "time_remaining": 90,
                "access_status": "Unlocked",
            },
            host="192.168.1.10",
        )
        self.assertEqual(info["ip"], "192.168.1.10")
        self.assertEqual(info["hostname"], "KidPC")
        self.assertFalse(info["locked"])
        self.assertEqual(info["usage_limit"], 120)
        self.assertEqual(info["time_remaining"], "90 minutes")
        self.assertTrue(info["reachable"])

    def test_legacy_access_status_when_missing(self) -> None:
        info = settings_to_pc_info(
            {"status": "LOCKED", "manual_lock": True},
            host="10.0.0.1",
            hostname_fallback="FallbackPC",
        )
        self.assertEqual(info["hostname"], "FallbackPC")
        self.assertTrue(info["locked"])
        self.assertEqual(info["access_status"], "Locked — manual lock")

    def test_no_port_kwarg(self) -> None:
        info = settings_to_pc_info({"status": "UNLOCKED"}, host="10.0.0.2")
        self.assertNotIn("port", info)


if __name__ == "__main__":
    unittest.main()

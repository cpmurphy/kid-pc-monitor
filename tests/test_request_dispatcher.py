"""Tests for request dispatch (request_dispatcher.py) and handle_request (pc_control.py)."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from typing import cast
from unittest import mock

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.agent_protocol import ProtocolError
from kid_pc_monitor.pc_control import PCTimeControl, handle_request
from test_pc_control import FakeHostPlatform

SECRET = "test-shared-secret"
HOSTNAME = "kid-pc"


class DispatchTests(unittest.TestCase):
    _UNSET = object()

    def _control(self, tmp: str, **kwargs) -> PCTimeControl:
        return PCTimeControl(
            platform=FakeHostPlatform(**kwargs),
            data_directory=Path(tmp),
            start_background_threads=False,
        )

    def _handle(
        self,
        control: PCTimeControl,
        *,
        name: str | None | object = _UNSET,
        version: int = proto.CLIENT_DEFAULT_VERSION,
        **req_kwargs,
    ) -> proto.Response:
        hostname = control.platform.get_hostname()
        # Default to a correctly-addressed, signed frame; tests can pass
        # ``name=None`` for the read-only discovery path.
        target = hostname if name is self._UNSET else cast(str | None, name)
        body = proto.build_request(
            secret=SECRET, req_id="r1", name=target, version=version, **req_kwargs
        )
        resp_body = handle_request(control, body, secret=SECRET)
        return proto.parse_response(
            resp_body,
            secret=SECRET,
            expected_name=hostname,
            expected_version=version,
        )

    def test_get_settings_returns_all_variables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            control.set_daily_allowance(90)
            control.set_bed_time(21, 0)
            resp = self._handle(control, action="get", var="settings")
            self.assertTrue(resp.ok)
            settings = resp.settings
            assert settings is not None
            self.assertEqual(settings["name"], "kid-pc")
            self.assertEqual(settings["daily_limit"], 90)
            self.assertEqual(settings["bed_time"], "21:00")
            self.assertEqual(settings["status"], "UNLOCKED")
            self.assertIs(settings["manual_lock"], False)
            self.assertIs(settings["enforcement_active"], False)
            self.assertIsNone(settings["enforcement_reason"])
            self.assertEqual(settings["access_status"], "Unlocked")

    def test_get_settings_manual_lock_access_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            control.runtime.manual_lock_active = True
            resp = self._handle(control, action="get", var="settings")
            self.assertTrue(resp.ok)
            settings = resp.settings
            assert settings is not None
            self.assertFalse(settings["enforcement_active"])
            self.assertEqual(settings["access_status"], "Locked — manual lock")

    def test_get_settings_enforcement_with_manual_lock(self) -> None:
        fixed = datetime(2026, 5, 17, 21, 5)
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            control.set_bed_time(21, 0)
            control.runtime.manual_lock_active = True
            with mock.patch("kid_pc_monitor.pc_control.datetime") as mock_dt:
                mock_dt.now.return_value = fixed
                resp = self._handle(control, action="get", var="settings")
            settings = resp.settings
            assert settings is not None
            self.assertTrue(settings["enforcement_active"])
            self.assertEqual(settings["enforcement_reason"], "past bedtime")
            self.assertEqual(settings["access_status"], "Locked — past bedtime")
            self.assertTrue(settings["manual_lock"])

    def test_get_single_variable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.set_daily_allowance(45)
            resp = self._handle(control, action="get", var="daily_limit")
            self.assertEqual(resp.result, 45)

    def test_get_name_without_name_field(self) -> None:
        # The discovery handshake: an unnamed read still returns a signed,
        # named response so the panel learns the hostname.
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            resp = self._handle(control, action="get", var="name", name=None)
            self.assertTrue(resp.ok)
            self.assertEqual(resp.result, "kid-pc")
            self.assertEqual(resp.name, "kid-pc")

    def test_set_daily_limit_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="daily_limit", val=120)
            self.assertTrue(resp.ok)
            self.assertEqual(control.daily.allowance, 120)

    def test_set_daily_limit_out_of_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="daily_limit", val=99999)
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_VALUE)
            self.assertIsNone(control.daily.allowance)

    def test_set_bed_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="bed_time", val="21:30")
            self.assertTrue(resp.ok)
            self.assertEqual(control.daily.bed_time, dtime(21, 30))

    def test_set_bad_time_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="wake_time", val="25:00")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_VALUE)

    def test_set_read_only_variable_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="status", val="LOCKED")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.FORBIDDEN)

    def test_set_manual_lock_locks_pc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="manual_lock", val=True)
            self.assertTrue(resp.ok)
            self.assertTrue(control.runtime.manual_lock_active)
            platform = control.platform
            assert isinstance(platform, FakeHostPlatform)
            self.assertEqual(platform.lock_calls, 1)

    def test_lock_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="lock")
            self.assertEqual(resp.result, "locked")
            self.assertTrue(control.runtime.manual_lock_active)

    def test_unlock_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.runtime.manual_lock_active = True
            resp = self._handle(control, action="unlock")
            self.assertEqual(resp.result, "unlocked")
            self.assertFalse(control.runtime.manual_lock_active)

    def test_clear_daily_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.set_daily_allowance(60)
            resp = self._handle(control, action="clear", var="daily_limit")
            self.assertTrue(resp.ok)
            self.assertIsNone(control.daily.allowance)

    def test_clear_read_only_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="clear", var="status")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.FORBIDDEN)

    def test_extend_adds_to_extension_without_resetting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.runtime.cumulative_extension_seconds = 600
            control.runtime.accumulated_seconds = 300.0
            resp = self._handle(control, action="extend", val=15)
            self.assertTrue(resp.ok)
            # Extension grows; usage already accumulated is left untouched.
            self.assertEqual(control.runtime.cumulative_extension_seconds, 600 + 15 * 60)
            self.assertEqual(control.runtime.accumulated_seconds, 300.0)

    def test_extend_requires_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="extend")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_REQUEST)

    def test_message_shows_popup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="message", val="dinner time")
            self.assertTrue(resp.ok)
            platform = control.platform
            assert isinstance(platform, FakeHostPlatform)
            self.assertIn(("PC Time Control", "dinner time"), platform.messages)

    def test_shutdown_default_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self.assertTrue(self._handle(control, action="shutdown").ok)
            self.assertTrue(self._handle(control, action="shutdown", val=30).ok)
            platform = control.platform
            assert isinstance(platform, FakeHostPlatform)
            self.assertEqual(platform.shutdown_calls, [60, 30])

    def test_lock_unlock_log_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._handle(control, action="lock")
            output = "\n".join(logs.output)
            self.assertIn("Parent action: manual lock engaged", output)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._handle(control, action="unlock")
            self.assertIn("Parent action: manual lock cleared", "\n".join(logs.output))

    def test_extend_logs_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._handle(control, action="extend", val=30)
            self.assertIn("Parent action: extended time by 30 minutes", "\n".join(logs.output))

    def test_shutdown_logs_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._handle(control, action="shutdown", val=45)
            self.assertIn("Parent action: shutdown in 45s", "\n".join(logs.output))

    def test_set_and_clear_log_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._handle(control, action="set", var="daily_limit", val=120)
                self._handle(control, action="clear", var="daily_limit")
                self._handle(control, action="set", var="bed_time", val="21:30")
                self._handle(control, action="clear", var="bed_time")
                self._handle(control, action="set", var="wake_time", val="07:00")
                self._handle(control, action="extend", val=10)
                self._handle(control, action="clear", var="cumulative_extension")
                self._handle(control, action="set", var="manual_lock", val=True)
                self._handle(control, action="clear", var="manual_lock")
            output = "\n".join(logs.output)
            self.assertIn("Parent action: daily limit set to 120 minutes", output)
            self.assertIn("Parent action: daily limit cleared", output)
            self.assertIn("Parent action: bed time set to 21:30", output)
            self.assertIn("Parent action: bed time cleared", output)
            self.assertIn("Parent action: wake time set to 07:00", output)
            self.assertIn("Parent action: extended time by 10 minutes", output)
            self.assertIn("Parent action: time extensions cleared", output)
            self.assertIn("Parent action: manual lock engaged", output)
            self.assertIn("Parent action: manual lock cleared", output)

    def test_message_logs_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._handle(control, action="message", val="dinner time")
            self.assertIn("Parent action: message sent: dinner time", "\n".join(logs.output))

    def test_list_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="list_capabilities", name=None)
            self.assertTrue(resp.ok)

    def test_v3_get_logs_returns_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            log_path = Path(tmp) / "pc_control.log"
            log_path.write_text("line one\nline two\nline three\n", encoding="utf-8")
            resp = self._handle(control, action="get_logs", version=3, tail=2)
            self.assertTrue(resp.ok)
            self.assertEqual(resp.version, 3)
            self.assertIsNotNone(resp.logs)
            assert resp.logs is not None
            self.assertEqual(resp.logs.lines, ["line two", "line three"])
            self.assertTrue(resp.logs.truncated)

    def test_v3_get_logs_tail_from_large_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            log_path = Path(tmp) / "pc_control.log"
            with log_path.open("w", encoding="utf-8") as handle:
                for i in range(10_000):
                    handle.write(f"line {i}\n")
            resp = self._handle(control, action="get_logs", version=3, tail=3)
            self.assertTrue(resp.ok)
            assert resp.logs is not None
            self.assertEqual(resp.logs.lines, ["line 9997", "line 9998", "line 9999"])
            self.assertTrue(resp.logs.truncated)

    def test_unsupported_version_v4(self) -> None:
        body = proto.build_request("get", secret=SECRET, var="name", version=3)
        body = body.replace("v 3", "v 4", 1)
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request(body, secret=SECRET, hostname=HOSTNAME)
        self.assertEqual(ctx.exception.code, proto.UNSUPPORTED_VERSION)

    def test_unsupported_version_v5(self) -> None:
        body = proto.build_request("get", secret=SECRET, var="name", version=3)
        body = body.replace("v 3", "v 5", 1)
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request(body, secret=SECRET, hostname=HOSTNAME)
        self.assertEqual(ctx.exception.code, proto.UNSUPPORTED_VERSION)

    def test_unauthenticated_request_yields_signed_failure(self) -> None:
        # The agent still signs its rejection so the panel can trust the error.
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            body = "this is not valid"
            resp_body = handle_request(control, body, secret=SECRET)
            resp = proto.parse_response(resp_body, secret=SECRET, expected_name="kid-pc")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_REQUEST)

    def test_tampered_request_yields_auth_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            body = proto.build_request(
                "set", secret=SECRET, var="daily_limit", val=120, name="kid-pc"
            )
            tampered = body.replace("val 120", "val 999")
            resp_body = handle_request(control, tampered, secret=SECRET)
            resp = proto.parse_response(resp_body, secret=SECRET, expected_name="kid-pc")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.AUTHENTICATION_FAILED)
            self.assertIsNone(control.daily.allowance)

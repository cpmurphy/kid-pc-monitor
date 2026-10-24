"""Tests for request_dispatcher.dispatch against a control object."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any
from unittest import mock

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.agent_protocol import Node, ProtocolError, Request
from kid_pc_monitor.pc_time_control import PCTimeControl
from kid_pc_monitor.request_dispatcher import dispatch
from test_pc_time_control import FakeHostPlatform


def _req(
    action: str,
    *,
    version: int = proto.CLIENT_DEFAULT_VERSION,
    req_id: str | None = "r1",
    var: str | None = None,
    val: Any = None,
    name: str | None = "kid-pc",
    tail: int | None = None,
) -> Request:
    return Request(version, req_id, action, var, val, name=name, tail=tail)


def _by_name(nodes: list[Node]) -> dict[str, Node]:
    return {node.name: node for node in nodes}


def _assert_ok(nodes: list[Node]) -> None:
    assert _by_name(nodes)["status"].arg == "ok"


def _result(nodes: list[Node]) -> Any:
    _assert_ok(nodes)
    result_node = _by_name(nodes).get("result")
    return None if result_node is None else result_node.arg


def _settings(nodes: list[Node]) -> dict[str, Any]:
    _assert_ok(nodes)
    return _by_name(nodes)["settings"].child_map()


def _logs(nodes: list[Node]) -> tuple[str, list[str], bool]:
    _assert_ok(nodes)
    block = _by_name(nodes)["logs"]
    fields = block.child_map()
    lines_node = next(child for child in block.children if child.name == "lines")
    line_texts = [str(arg) for arg in lines_node.args]
    return str(fields.get("path", "")), line_texts, bool(fields.get("truncated"))


class DispatchTests(unittest.TestCase):
    def _control(self, tmp: str, **kwargs) -> PCTimeControl:
        return PCTimeControl(
            platform=FakeHostPlatform(**kwargs),
            data_directory=Path(tmp),
            start_background_threads=False,
        )

    def _dispatch(self, control: PCTimeControl, req: Request) -> list[Node]:
        return dispatch(control, req)

    def _dispatch_ok(self, control: PCTimeControl, **req_kwargs: Any) -> Any:
        return _result(self._dispatch(control, _req(**req_kwargs)))

    def _dispatch_settings(self, control: PCTimeControl, **req_kwargs: Any) -> dict[str, Any]:
        return _settings(self._dispatch(control, _req(**req_kwargs)))

    def _dispatch_logs(
        self, control: PCTimeControl, **req_kwargs: Any
    ) -> tuple[str, list[str], bool]:
        return _logs(self._dispatch(control, _req(**req_kwargs)))

    def test_get_settings_returns_all_variables(self) -> None:
        # Pin wall clock before bedtime so this is stable in UTC CI overnight.
        fixed = datetime(2026, 5, 17, 15, 0)
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            control.set_daily_allowance(90)
            control.set_bed_time(21, 0)
            with mock.patch("kid_pc_monitor.pc_time_control.datetime", wraps=datetime) as mock_dt:
                mock_dt.now.return_value = fixed
                settings = self._dispatch_settings(control, action="get", var="settings")
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
            settings = self._dispatch_settings(control, action="get", var="settings")
            self.assertFalse(settings["enforcement_active"])
            self.assertEqual(settings["access_status"], "Locked — manual lock")

    def test_get_settings_enforcement_with_manual_lock(self) -> None:
        fixed = datetime(2026, 5, 17, 21, 5)
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            control.set_bed_time(21, 0)
            control.runtime.manual_lock_active = True
            with mock.patch("kid_pc_monitor.pc_time_control.datetime") as mock_dt:
                mock_dt.now.return_value = fixed
                settings = self._dispatch_settings(control, action="get", var="settings")
            self.assertTrue(settings["enforcement_active"])
            self.assertEqual(settings["enforcement_reason"], "past bedtime")
            self.assertEqual(settings["access_status"], "Locked — past bedtime")
            self.assertTrue(settings["manual_lock"])

    def test_get_single_variable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.set_daily_allowance(45)
            self.assertEqual(
                self._dispatch_ok(control, action="get", var="daily_limit"),
                45,
            )

    def test_get_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            self.assertEqual(
                self._dispatch_ok(control, action="get", var="name", name=None),
                "kid-pc",
            )

    def test_set_daily_limit_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self._dispatch_ok(control, action="set", var="daily_limit", val=120)
            self.assertEqual(control.daily.allowance, 120)

    def test_set_daily_limit_out_of_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertRaises(ProtocolError) as ctx:
                self._dispatch(control, _req(action="set", var="daily_limit", val=99999))
            self.assertEqual(ctx.exception.code, proto.INVALID_VALUE)
            self.assertIsNone(control.daily.allowance)

    def test_set_bed_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self._dispatch_ok(control, action="set", var="bed_time", val="21:30")
            self.assertEqual(control.daily.bed_time, dtime(21, 30))

    def test_set_bad_time_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertRaises(ProtocolError) as ctx:
                self._dispatch(control, _req(action="set", var="wake_time", val="25:00"))
            self.assertEqual(ctx.exception.code, proto.INVALID_VALUE)

    def test_set_read_only_variable_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertRaises(ProtocolError) as ctx:
                self._dispatch(control, _req(action="set", var="status", val="LOCKED"))
            self.assertEqual(ctx.exception.code, proto.FORBIDDEN)

    def test_set_manual_lock_locks_pc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self._dispatch_ok(control, action="set", var="manual_lock", val=True)
            self.assertTrue(control.runtime.manual_lock_active)
            platform = control.platform
            assert isinstance(platform, FakeHostPlatform)
            self.assertEqual(platform.lock_calls, 1)

    def test_lock_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self.assertEqual(self._dispatch_ok(control, action="lock"), "locked")
            self.assertTrue(control.runtime.manual_lock_active)

    def test_unlock_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.runtime.manual_lock_active = True
            self.assertEqual(self._dispatch_ok(control, action="unlock"), "unlocked")
            self.assertFalse(control.runtime.manual_lock_active)

    def test_clear_daily_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.set_daily_allowance(60)
            self._dispatch_ok(control, action="clear", var="daily_limit")
            self.assertIsNone(control.daily.allowance)

    def test_clear_read_only_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertRaises(ProtocolError) as ctx:
                self._dispatch(control, _req(action="clear", var="status"))
            self.assertEqual(ctx.exception.code, proto.FORBIDDEN)

    def test_extend_adds_to_extension_without_resetting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.runtime.cumulative_extension_seconds = 600
            control.runtime.accumulated_seconds = 300.0
            self._dispatch_ok(control, action="extend", val=15)
            self.assertEqual(control.runtime.cumulative_extension_seconds, 600 + 15 * 60)
            self.assertEqual(control.runtime.accumulated_seconds, 300.0)

    def test_message_shows_popup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self._dispatch_ok(control, action="message", val="dinner time")
            platform = control.platform
            assert isinstance(platform, FakeHostPlatform)
            self.assertIn(("PC Time Control", "dinner time"), platform.messages)

    def test_shutdown_default_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self._dispatch_ok(control, action="shutdown")
            self._dispatch_ok(control, action="shutdown", val=30)
            platform = control.platform
            assert isinstance(platform, FakeHostPlatform)
            self.assertEqual(platform.shutdown_calls, [60, 30])

    def test_lock_unlock_log_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._dispatch_ok(control, action="lock")
            output = "\n".join(logs.output)
            self.assertIn("Parent action: manual lock engaged", output)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._dispatch_ok(control, action="unlock")
            self.assertIn("Parent action: manual lock cleared", "\n".join(logs.output))

    def test_extend_logs_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._dispatch_ok(control, action="extend", val=30)
            self.assertIn("Parent action: extended time by 30 minutes", "\n".join(logs.output))

    def test_shutdown_logs_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._dispatch_ok(control, action="shutdown", val=45)
            self.assertIn("Parent action: shutdown in 45s", "\n".join(logs.output))

    def test_set_and_clear_log_parent_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                self._dispatch_ok(control, action="set", var="daily_limit", val=120)
                self._dispatch_ok(control, action="clear", var="daily_limit")
                self._dispatch_ok(control, action="set", var="bed_time", val="21:30")
                self._dispatch_ok(control, action="clear", var="bed_time")
                self._dispatch_ok(control, action="set", var="wake_time", val="07:00")
                self._dispatch_ok(control, action="extend", val=10)
                self._dispatch_ok(control, action="clear", var="cumulative_extension")
                self._dispatch_ok(control, action="set", var="manual_lock", val=True)
                self._dispatch_ok(control, action="clear", var="manual_lock")
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
                self._dispatch_ok(control, action="message", val="dinner time")
            self.assertIn("Parent action: message sent: dinner time", "\n".join(logs.output))

    def test_list_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            nodes = self._dispatch(control, _req(action="list_capabilities", name=None))
            _assert_ok(nodes)
            by_name = _by_name(nodes)
            self.assertIn("get", by_name["actions"].child_map())
            self.assertIn("daily_limit", by_name["values"].child_map())

    def test_v3_get_logs_returns_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            log_path = Path(tmp) / "pc_control.log"
            log_path.write_text("line one\nline two\nline three\n", encoding="utf-8")
            _path, lines, truncated = self._dispatch_logs(
                control, action="get_logs", version=3, tail=2
            )
            self.assertEqual(lines, ["line two", "line three"])
            self.assertTrue(truncated)

    def test_v3_get_logs_tail_from_large_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            log_path = Path(tmp) / "pc_control.log"
            with log_path.open("w", encoding="utf-8") as handle:
                for i in range(10_000):
                    handle.write(f"line {i}\n")
            _path, lines, truncated = self._dispatch_logs(
                control, action="get_logs", version=3, tail=3
            )
            self.assertEqual(lines, ["line 9997", "line 9998", "line 9999"])
            self.assertTrue(truncated)


class StrictInputTests(unittest.TestCase):
    """Values from the wire are validated, not coerced."""

    def _control(self, tmp: str) -> PCTimeControl:
        return PCTimeControl(
            platform=FakeHostPlatform(),
            data_directory=Path(tmp),
            start_background_threads=False,
        )

    def _code(self, control: PCTimeControl, req: Request) -> str:
        with self.assertRaises(ProtocolError) as ctx:
            dispatch(control, req)
        return ctx.exception.code

    def test_times_must_be_strict_hh_mm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            dispatch(control, _req("set", var="bed_time", val="9:30"))
            self.assertEqual(control.daily.bed_time, dtime(9, 30))
            for bad in ("7:5", "07:00:00", "5_0:00", "+7:00", "٧:٠٠", 730, True, "", "24:00"):
                code = self._code(control, _req("set", var="wake_time", val=bad))
                self.assertEqual(code, proto.INVALID_VALUE, bad)

    def test_numbers_must_be_plain_decimal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            dispatch(control, _req("set", var="daily_limit", val=" 90 "))
            self.assertEqual(control.daily.allowance, 90)
            for bad in ("1_0", "٩٠", "9.5", "", True, 2**60, "9" * 30):
                code = self._code(control, _req("set", var="daily_limit", val=bad))
                self.assertEqual(code, proto.INVALID_VALUE, repr(bad))

    def test_extend_must_add_a_sensible_number_of_minutes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            dispatch(control, _req("extend", val=30))
            self.assertEqual(control.runtime.cumulative_extension_seconds, 1800)
            for bad in (0, -30, 1441, "x", None):
                code = self._code(control, _req("extend", val=bad))
                self.assertIn(code, (proto.INVALID_VALUE, proto.INVALID_REQUEST), repr(bad))
            self.assertEqual(control.runtime.cumulative_extension_seconds, 1800)

    def test_extension_survives_a_save_and_reload(self) -> None:
        # Anything the dispatcher accepts must be something the state file accepts.
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            dispatch(control, _req("extend", val=1440))
            reloaded = self._control(tmp)
            self.assertEqual(reloaded.runtime.cumulative_extension_seconds, 1440 * 60)
            self.assertEqual(reloaded.state_store.problems, [])

    def test_message_must_be_non_empty_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            platform = control.platform
            dispatch(control, _req("message", val="Dinner!\n"))
            assert isinstance(platform, FakeHostPlatform)
            self.assertEqual([text for _title, text in platform.messages], ["Dinner!\n"])
            for bad in ("", "   ", 5, True, None):
                self.assertEqual(
                    self._code(control, _req("message", val=bad)), proto.INVALID_VALUE, repr(bad)
                )

    def test_manual_lock_accepts_the_documented_spellings_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            for good, want in (
                (True, True),
                ("Yes", True),
                ("1", True),
                (1, True),
                ("no", False),
                (0, False),
            ):
                dispatch(control, _req("set", var="manual_lock", val=good))
                self.assertIs(control.runtime.manual_lock_active, want, good)
            for bad in ("maybe", 2, 1.5, None, ""):
                code = self._code(control, _req("set", var="manual_lock", val=bad))
                self.assertIn(code, (proto.INVALID_VALUE, proto.INVALID_REQUEST), repr(bad))


class FitLogLinesTests(unittest.TestCase):
    """The single-pass fit must cut exactly where re-serializing after every drop does."""

    @staticmethod
    def _slow(path: str, lines: list[str], truncated: bool) -> tuple[list[str], bool]:
        from kid_pc_monitor import request_dispatcher as rd

        budget = proto.MAX_FRAME_BYTES - 1024
        while lines and rd._logs_block_byte_size(path, lines, truncated) > budget:
            lines = lines[1:]
            truncated = True
        return lines, truncated

    def test_matches_the_straightforward_loop(self) -> None:
        from kid_pc_monitor import request_dispatcher as rd

        samples = [
            [],
            ["short"],
            [f'[2026-05-31 12:00:{i % 60:02d}] INFO line {i} "q" ünï' for i in range(2000)],
            ["x" * 5000] * 20,
            ["é" * 100, "plain", "tab\tnewline\n"] * 400,
            ["true", "null", "123", "", "a b"] * 500,
        ]
        for lines in samples:
            for truncated in (False, True):
                path = "C:\\logs\\pc_control.log"
                self.assertEqual(
                    rd._fit_log_lines_to_frame(path, list(lines), truncated),
                    self._slow(path, list(lines), truncated),
                )

    def test_an_oversized_path_drops_every_line(self) -> None:
        from kid_pc_monitor import request_dispatcher as rd

        lines, truncated = rd._fit_log_lines_to_frame("p" * 70_000, ["a", "b"], False)
        self.assertEqual((lines, truncated), ([], True))


if __name__ == "__main__":
    unittest.main()

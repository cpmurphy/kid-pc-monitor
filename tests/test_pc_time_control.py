"""Tests for PCTimeControl orchestration with a fake HostPlatform."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from datetime import time as dtime
from pathlib import Path
from unittest import mock

from kid_pc_monitor.agent_state import AgentStateStore
from kid_pc_monitor.host_platform import HostPlatform
from kid_pc_monitor.pc_time_control import PCTimeControl


class FakeHostPlatform(HostPlatform):
    """In-memory platform stub for unit tests."""

    def __init__(
        self,
        *,
        locked: bool = False,
        session_active: bool = True,
        hostname: str = "test-pc",
    ) -> None:
        self.locked = locked
        self.session_active = session_active
        self.hostname = hostname
        self.lock_calls = 0
        self.shutdown_calls: list[int] = []
        self.messages: list[tuple[str, str]] = []

    def check_session_locked(self) -> bool:
        return self.locked

    def session_is_active(self) -> bool:
        return self.session_active and not self.locked

    def lock_workstation(self) -> None:
        self.lock_calls += 1
        self.locked = True

    def shutdown(self, seconds: int = 60) -> None:
        self.shutdown_calls.append(seconds)

    def cancel_shutdown(self) -> None:
        pass

    def show_message(self, message: str, title: str = "PC Time Control") -> None:
        self.messages.append((title, message))

    def get_hostname(self) -> str:
        return self.hostname


class PCTimeControlTests(unittest.TestCase):
    def test_should_monitor_user_respects_exempt_list(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                exempt_users=["parent"],
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.current_user = "parent"
            self.assertFalse(control.should_monitor_user())
            control.current_user = "kid"
            self.assertTrue(control.should_monitor_user())

    def test_load_and_save_state_round_trip(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            control = PCTimeControl(
                platform=platform,
                data_directory=data_dir,
                start_background_threads=False,
            )
            control.set_bed_time(21, 0)
            control.set_daily_allowance(90)
            control.runtime.manual_lock_active = True
            control.runtime.accumulated_seconds = 120.0
            control.runtime.cumulative_extension_seconds = 900
            control.save_state()

            reloaded = PCTimeControl(
                platform=platform,
                data_directory=data_dir,
                start_background_threads=False,
            )
            self.assertEqual(reloaded.daily.bed_time, dtime(21, 0))
            self.assertEqual(reloaded.daily.allowance, 90)
            self.assertTrue(reloaded.runtime.manual_lock_active)
            self.assertAlmostEqual(reloaded.runtime.accumulated_seconds, 120.0)
            self.assertEqual(reloaded.runtime.cumulative_extension_seconds, 900)

    def test_failed_load_does_not_overwrite_state_files_with_defaults(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            first = PCTimeControl(
                platform=platform, data_directory=data_dir, start_background_threads=False
            )
            first.set_daily_allowance(90)
            first.save_state()
            before = (data_dir / "daily_settings.json").read_text(encoding="utf-8")

            with mock.patch.object(
                AgentStateStore, "load", side_effect=PermissionError("file in use")
            ):
                second = PCTimeControl(
                    platform=platform, data_directory=data_dir, start_background_threads=False
                )
                self.assertTrue(second.state_load_failed)
                second.save_state()  # would write built-in defaults (no allowance)
            self.assertEqual((data_dir / "daily_settings.json").read_text(encoding="utf-8"), before)

            # Once the files are readable again the agent recovers its settings.
            second.save_state()
            self.assertFalse(second.state_load_failed)
            self.assertEqual(second.daily.allowance, 90)

    def test_tick_accumulator_only_while_session_active(self) -> None:
        platform = FakeHostPlatform(session_active=True, locked=False)
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.last_tick_at = datetime.now() - timedelta(seconds=30)
            control.tick_accumulator()
            self.assertGreater(control.runtime.accumulated_seconds, 0.0)

            before = control.runtime.accumulated_seconds
            platform.session_active = False
            control.tick_accumulator()
            self.assertEqual(control.runtime.accumulated_seconds, before)

    def test_tick_accumulator_does_not_count_while_locked(self) -> None:
        platform = FakeHostPlatform(session_active=True, locked=True)
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.last_tick_at = datetime.now() - timedelta(seconds=30)
            control.tick_accumulator()
            self.assertEqual(control.runtime.accumulated_seconds, 0.0)

    def test_tick_accumulator_skips_during_bedtime_curfew(self) -> None:
        platform = FakeHostPlatform(session_active=True, locked=False)
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            # Build a curfew around "now": the only awake minute is [now+1, now+2),
            # so the current instant is always inside the curfew regardless of when
            # the test runs (handles midnight wraparound too).
            now = datetime.now()
            wake = (now + timedelta(minutes=1)).time()
            bed = (now + timedelta(minutes=2)).time()
            control.set_wake_time(wake.hour, wake.minute)
            control.set_bed_time(bed.hour, bed.minute)
            in_window, _ = control.currently_in_lock_window()
            self.assertTrue(in_window)
            control.last_tick_at = now - timedelta(seconds=30)
            control.tick_accumulator()
            self.assertEqual(control.runtime.accumulated_seconds, 0.0)

    def test_set_wake_time_before_now_resets_daily_runtime(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.daily.wake_time = dtime(9, 0)
            control.runtime.timestamp = datetime(2026, 6, 6, 7, 8)
            control.runtime.accumulated_seconds = 14_400
            control.runtime.manual_lock_active = True
            control.runtime.cumulative_extension_seconds = 3600

            with mock.patch(
                "kid_pc_monitor.pc_time_control.datetime", wraps=datetime
            ) as mocked_datetime:
                mocked_datetime.now.return_value = datetime(2026, 6, 6, 7, 9)
                with self.assertLogs("PCTimeControl", level="INFO") as logs:
                    control.set_wake_time(7, 0)

            self.assertEqual(control.daily.wake_time, dtime(7, 0))
            self.assertEqual(control.runtime.timestamp, datetime(2026, 6, 6, 7, 9))
            self.assertEqual(control.runtime.accumulated_seconds, 0.0)
            self.assertFalse(control.runtime.manual_lock_active)
            self.assertEqual(control.runtime.cumulative_extension_seconds, 0)
            self.assertIsNone(control.last_tick_at)
            self.assertIn(
                "Wake-time change (09:00 -> 07:00): resetting daily runtime state",
                "\n".join(logs.output),
            )

    def test_set_wake_time_later_than_now_keeps_daily_runtime(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.daily.wake_time = dtime(7, 0)
            control.runtime.timestamp = datetime(2026, 6, 6, 7, 8)
            control.runtime.accumulated_seconds = 120

            with mock.patch(
                "kid_pc_monitor.pc_time_control.datetime", wraps=datetime
            ) as mocked_datetime:
                mocked_datetime.now.return_value = datetime(2026, 6, 6, 8, 0)
                control.set_wake_time(9, 0)

            self.assertEqual(control.daily.wake_time, dtime(9, 0))
            self.assertAlmostEqual(control.runtime.accumulated_seconds, 120.0)

    def test_extend_time_adds_to_cumulative_extension_only(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.set_daily_allowance(60)
            control.runtime.accumulated_seconds = 100.0
            control.extend_time(30)
            self.assertEqual(control.daily.allowance, 60)
            self.assertAlmostEqual(control.runtime.accumulated_seconds, 100.0)
            self.assertEqual(control.runtime.cumulative_extension_seconds, 1800)

    def test_extend_time_clears_manual_lock(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.runtime.manual_lock_active = True
            control.extend_time(15)
            self.assertFalse(control.runtime.manual_lock_active)
            self.assertEqual(control.runtime.cumulative_extension_seconds, 900)
            locked, _ = control.currently_in_lock_window()
            self.assertFalse(locked)

    def test_extend_time_resets_warning_tracking(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.warnings_sent = {"30min", "15min", "5min", "1min"}

            with mock.patch.object(control, "get_time_remaining", return_value=14.0):
                control.check_and_send_warnings()
            self.assertEqual(platform.messages, [])

            control.extend_time(30)

            self.assertEqual(control.warnings_sent, set())
            with mock.patch.object(control, "get_time_remaining", return_value=14.0):
                control.check_and_send_warnings()
            self.assertEqual(len(platform.messages), 1)
            self.assertIn("14 minutes", platform.messages[0][1])

    def test_currently_in_lock_window_manual_lock(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.runtime.manual_lock_active = True
            locked, reason = control.currently_in_lock_window()
            self.assertTrue(locked)
            self.assertIn("Manual", reason)

    def test_lock_pc_delegates_to_platform(self) -> None:
        platform = FakeHostPlatform(locked=False)
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.lock_pc()
            self.assertEqual(platform.lock_calls, 1)
            self.assertTrue(platform.locked)

    def test_engage_manual_lock_logs_parent_action(self) -> None:
        platform = FakeHostPlatform(locked=False)
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                control.engage_manual_lock()
            self.assertIn("Parent action: manual lock engaged", "\n".join(logs.output))
            self.assertTrue(control.runtime.manual_lock_active)

    def test_send_parent_message_logs_truncated_preview(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            long_text = "x" * 150
            with self.assertLogs("PCTimeControl", level="INFO") as logs:
                control.send_parent_message(long_text)
            output = "\n".join(logs.output)
            self.assertIn("Parent action: message sent:", output)
            self.assertIn("...", output)
            self.assertNotIn("x" * 150, output)

    def test_bootstraps_wake_time_from_program_data_daily(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            program_data = data_dir / "ProgramData" / "KidPCMonitor"
            program_data.mkdir(parents=True)
            (program_data / "daily_settings.json").write_text(
                '{"target_user": "kid", "wake_time": "08:30"}',
                encoding="utf-8",
            )
            old_win = sys.platform
            try:
                sys.platform = "win32"
                from unittest.mock import patch

                from kid_pc_monitor import agent_state as agent_state_mod

                original = agent_state_mod.program_data_daily_path
                agent_state_mod.program_data_daily_path = lambda: (
                    program_data / "daily_settings.json"
                )
                try:
                    with patch("getpass.getuser", return_value="kid"):
                        control = PCTimeControl(
                            platform=platform,
                            data_directory=data_dir / "profile",
                            start_background_threads=False,
                        )
                finally:
                    agent_state_mod.program_data_daily_path = original
            finally:
                sys.platform = old_win

            self.assertEqual(control.daily.wake_time, dtime(8, 30))
            self.assertTrue((data_dir / "profile" / "daily_settings.json").is_file())

    def test_check_if_locked_delegates_to_platform(self) -> None:
        platform = FakeHostPlatform(locked=True)
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            self.assertTrue(control.check_if_locked())


class MonitorStepTests(unittest.TestCase):
    """monitor_step: phases are isolated and platform errors never stop enforcement."""

    def setUp(self) -> None:
        self.now = datetime(2026, 5, 17, 12, 0, 0)
        self.platform = FakeHostPlatform()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.control = PCTimeControl(
            platform=self.platform,
            data_directory=Path(tmp.name),
            start_background_threads=False,
            clock=lambda: self.now,
            current_user="kid",
            program_data_dir=None,
        )

    def test_failing_popup_does_not_stop_the_other_phases(self) -> None:
        self.control.daily.allowance = 10
        self.control.runtime.accumulated_seconds = 9.5 * 60

        def boom(message: str, title: str = "") -> None:
            raise RuntimeError("no desktop")

        self.platform.show_message = boom  # type: ignore[method-assign]
        with self.assertLogs("PCTimeControl", level="ERROR") as logs:
            self.control.monitor_step()
        self.assertEqual(
            logs.output,
            ["ERROR:PCTimeControl:Monitor phase check_and_send_warnings failed: no desktop"],
        )
        self.assertEqual(self.control.last_persist_at, self.now)
        self.assertEqual(self.control.warnings_sent, set())  # retried once the popup works

    def test_phase_error_is_logged_once_and_other_phases_still_run(self) -> None:
        self.control.engage_manual_lock()
        self.platform.locked = False
        self.platform.lock_calls = 0

        def broken() -> None:
            raise RuntimeError("bad")

        self.control.check_and_send_warnings = broken  # type: ignore[method-assign]
        with self.assertLogs("PCTimeControl", level="INFO") as logs:
            self.control.monitor_step()
            self.platform.locked = False
            self.control.monitor_step()
        self.assertEqual(self.platform.lock_calls, 2)
        self.assertEqual(
            [m for m in logs.output if "failed" in m],
            ["ERROR:PCTimeControl:Monitor phase check_and_send_warnings failed: bad"],
        )

    def test_platform_query_errors_fail_toward_enforcement(self) -> None:
        def broken() -> bool:
            raise OSError("wts down")

        self.platform.check_session_locked = broken  # type: ignore[method-assign]
        self.platform.session_is_active = broken  # type: ignore[method-assign]
        self.assertFalse(self.control.check_if_locked())
        self.assertTrue(self.control.session_is_active())

    def test_failed_lock_does_not_mark_pc_locked(self) -> None:
        def broken() -> None:
            raise OSError("no")

        self.platform.lock_workstation = broken  # type: ignore[method-assign]
        self.control.lock_pc()
        self.assertFalse(self.control.is_locked)

    def test_save_is_due_after_the_clock_goes_backwards(self) -> None:
        self.control.monitor_step()
        first = self.control.last_persist_at
        self.assertEqual(first, self.now)
        self.now += timedelta(seconds=30)
        self.control.monitor_step()
        self.assertEqual(self.control.last_persist_at, first)  # throttled
        self.now -= timedelta(hours=2)
        self.control.monitor_step()
        self.assertEqual(self.control.last_persist_at, self.now)  # not stalled


if __name__ == "__main__":
    unittest.main()

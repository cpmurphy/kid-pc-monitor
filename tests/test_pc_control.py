"""Tests for PCTimeControl orchestration with a fake HostPlatform."""

from __future__ import annotations

import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, time as dtime
from pathlib import Path

from kid_pc_monitor.host_platform import HostPlatform
from kid_pc_monitor.pc_control import PCTimeControl


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
            control.warnings_sent = {"15min", "5min", "1min"}

            with mock.patch.object(
                control, "get_time_remaining", return_value=14.0
            ):
                control.check_and_send_warnings()
            self.assertEqual(platform.messages, [])

            control.extend_time(30)

            self.assertEqual(control.warnings_sent, set())
            with mock.patch.object(
                control, "get_time_remaining", return_value=14.0
            ):
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
                from kid_pc_monitor import agent_state as agent_state_mod
                from unittest.mock import patch

                original = agent_state_mod.program_data_daily_path
                agent_state_mod.program_data_daily_path = lambda: program_data / "daily_settings.json"
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


if __name__ == "__main__":
    unittest.main()

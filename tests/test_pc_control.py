"""Tests for PCTimeControl orchestration with a fake HostPlatform."""

from __future__ import annotations

import sys
import tempfile
import unittest
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
            control.lock_times = [dtime(21, 0)]
            control.usage_limit = 90
            control.manual_lock_active = True
            control.accumulated_seconds = 120.0
            control.save_state()

            reloaded = PCTimeControl(
                platform=platform,
                data_directory=data_dir,
                start_background_threads=False,
            )
            self.assertEqual(reloaded.lock_times, [dtime(21, 0)])
            self.assertEqual(reloaded.usage_limit, 90)
            self.assertTrue(reloaded.manual_lock_active)
            self.assertAlmostEqual(reloaded.accumulated_seconds, 120.0)

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
            self.assertGreater(control.accumulated_seconds, 0.0)

            before = control.accumulated_seconds
            platform.session_active = False
            control.tick_accumulator()
            self.assertEqual(control.accumulated_seconds, before)

    def test_currently_in_lock_window_manual_lock(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=platform,
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            control.manual_lock_active = True
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

    def test_applies_wake_time_from_install_config_when_state_missing(self) -> None:
        platform = FakeHostPlatform()
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            program_data = data_dir / "ProgramData" / "KidPCMonitor"
            program_data.mkdir(parents=True)
            (program_data / "install_config.json").write_text(
                '{"target_user": "kid", "wake_time": "08:30"}',
                encoding="utf-8",
            )
            old_win = sys.platform
            try:
                sys.platform = "win32"
                control = PCTimeControl(
                    platform=platform,
                    data_directory=data_dir / "profile",
                    start_background_threads=False,
                )
                control.current_user = "kid"
                control._install_config_path = lambda: program_data / "install_config.json"  # type: ignore[method-assign]
                control.load_state()
            finally:
                sys.platform = old_win

            self.assertEqual(control.wake_time, dtime(8, 30))
            self.assertTrue((data_dir / "profile" / "pc_control_state.json").is_file())

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

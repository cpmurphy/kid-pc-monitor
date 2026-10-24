"""Tests for agent_state persistence and migration."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from unittest import mock

from kid_pc_monitor.agent_state import (
    AgentStateStore,
    DailySettings,
    RuntimeState,
    effective_daily_allowance_minutes,
    is_complete_daily_dict,
    load_daily_from_dict,
    load_runtime_from_dict,
    migrate_legacy_state,
    reset_runtime_for_new_period,
    reset_runtime_if_needed,
    runtime_state_is_current,
)


class AgentStateTests(unittest.TestCase):
    def test_effective_daily_allowance_includes_extensions(self) -> None:
        daily = DailySettings(bed_time=None, wake_time=dtime(7, 0), allowance=120)
        runtime = RuntimeState(
            timestamp=datetime.now(),
            accumulated_seconds=0,
            manual_lock_active=False,
            cumulative_extension_seconds=1800,
        )
        self.assertEqual(effective_daily_allowance_minutes(daily, runtime), 150)

    def test_effective_daily_allowance_none_without_base_or_extension(self) -> None:
        daily = DailySettings(bed_time=None, wake_time=dtime(7, 0), allowance=None)
        runtime = RuntimeState(
            timestamp=datetime.now(),
            accumulated_seconds=0,
            manual_lock_active=False,
            cumulative_extension_seconds=0,
        )
        self.assertIsNone(effective_daily_allowance_minutes(daily, runtime))

    def test_runtime_state_is_current_uses_wake_time_period(self) -> None:
        wake = dtime(7, 0)
        now = datetime(2026, 5, 18, 8, 0)
        runtime = RuntimeState(
            timestamp=datetime(2026, 5, 18, 7, 30),
            accumulated_seconds=0,
            manual_lock_active=False,
            cumulative_extension_seconds=0,
        )
        self.assertTrue(runtime_state_is_current(runtime, wake, now))

        old = RuntimeState(
            timestamp=datetime(2026, 5, 17, 20, 0),
            accumulated_seconds=100,
            manual_lock_active=True,
            cumulative_extension_seconds=600,
        )
        self.assertFalse(runtime_state_is_current(old, wake, now))

    def test_migrate_legacy_state_maps_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "pc_control_state.json"
            legacy.write_text(
                json.dumps(
                    {
                        "lock_times": ["21:00"],
                        "wake_time": "08:30",
                        "usage_allowance": 90,
                        "manual_lock_active": True,
                        "accumulated_seconds": 120,
                        "accumulated_date": datetime.now().date().isoformat(),
                    }
                ),
                encoding="utf-8",
            )
            migrated = migrate_legacy_state(legacy, current_user="kid")
            assert migrated is not None
            daily, runtime = migrated
            self.assertEqual(daily.bed_time, dtime(21, 0))
            self.assertEqual(daily.wake_time, dtime(8, 30))
            self.assertEqual(daily.allowance, 90)
            self.assertTrue(runtime.manual_lock_active)
            self.assertAlmostEqual(runtime.accumulated_seconds, 120.0)

    def test_store_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStateStore(Path(tmp), current_user="kid")
            daily = DailySettings(
                bed_time=dtime(21, 0),
                wake_time=dtime(7, 0),
                allowance=120,
            )
            runtime = RuntimeState(
                timestamp=datetime.now(),
                accumulated_seconds=300,
                manual_lock_active=False,
                cumulative_extension_seconds=900,
            )
            store.save(daily, runtime)
            loaded_daily, loaded_runtime = store.load()
            self.assertEqual(loaded_daily.bed_time, dtime(21, 0))
            self.assertEqual(loaded_daily.allowance, 120)
            self.assertAlmostEqual(loaded_runtime.accumulated_seconds, 300.0)
            self.assertEqual(loaded_runtime.cumulative_extension_seconds, 900)

    def test_store_resets_stale_runtime_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            daily_path = data_dir / "daily_settings.json"
            state_path = data_dir / "state.json"
            daily_path.write_text(
                json.dumps({"wake_time": "07:00", "bed_time": None, "allowance": 60}),
                encoding="utf-8",
            )
            state_path.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-01-01T12:00:00",
                        "accumulated_seconds": 999,
                        "manual_lock_active": True,
                        "cumulative_extension_seconds": 3600,
                    }
                ),
                encoding="utf-8",
            )
            store = AgentStateStore(data_dir, current_user="kid")
            _daily, runtime = store.load()
            self.assertFalse(runtime.manual_lock_active)
            self.assertEqual(runtime.accumulated_seconds, 0.0)
            self.assertEqual(runtime.cumulative_extension_seconds, 0)

    def test_reset_runtime_for_new_period_clears_daily_fields(self) -> None:
        runtime = RuntimeState(
            timestamp=datetime(2026, 1, 1, 12, 0),
            accumulated_seconds=500,
            manual_lock_active=True,
            cumulative_extension_seconds=1800,
        )
        reset_runtime_for_new_period(runtime, datetime(2026, 1, 2, 8, 0))
        self.assertEqual(runtime.accumulated_seconds, 0.0)
        self.assertFalse(runtime.manual_lock_active)
        self.assertEqual(runtime.cumulative_extension_seconds, 0)

    def test_reset_runtime_if_needed_resets_stale_period(self) -> None:
        runtime = RuntimeState(
            timestamp=datetime(2026, 6, 5, 10, 0),
            accumulated_seconds=14_400,
            manual_lock_active=True,
            cumulative_extension_seconds=3600,
        )
        did_reset = reset_runtime_if_needed(
            runtime,
            dtime(7, 0),
            datetime(2026, 6, 6, 7, 9),
        )
        self.assertTrue(did_reset)
        self.assertEqual(runtime.timestamp, datetime(2026, 6, 6, 7, 9))
        self.assertEqual(runtime.accumulated_seconds, 0.0)
        self.assertFalse(runtime.manual_lock_active)
        self.assertEqual(runtime.cumulative_extension_seconds, 0)

    def test_reset_runtime_if_needed_leaves_current_period_unchanged(self) -> None:
        runtime = RuntimeState(
            timestamp=datetime(2026, 6, 6, 7, 8),
            accumulated_seconds=120,
            manual_lock_active=False,
            cumulative_extension_seconds=0,
        )
        did_reset = reset_runtime_if_needed(
            runtime,
            dtime(7, 0),
            datetime(2026, 6, 6, 8, 0),
        )
        self.assertFalse(did_reset)
        self.assertAlmostEqual(runtime.accumulated_seconds, 120.0)


class StrictValueTests(unittest.TestCase):
    """Values are validated, not coerced: nothing here may quietly become something else."""

    def test_allowance_must_be_a_whole_non_negative_number(self) -> None:
        for good, want in ((90, 90), (90.0, 90), ("90", 90), (" 90 ", 90), (0, 0)):
            self.assertEqual(load_daily_from_dict({"allowance": good}).allowance, want, good)
        for bad in (True, False, 90.7, -1, "-1", "1.5", "abc", "", [], {}, 1e300, 2**60, "٣"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                load_daily_from_dict({"allowance": bad})

    def test_times_must_be_hh_mm_strings(self) -> None:
        self.assertEqual(load_daily_from_dict({"wake_time": "6:30"}).wake_time, dtime(6, 30))
        for bad in (700, None, True, ["07:00"], "7:5", "07:00:00", "５:00", "7_0:00", "+7:00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                load_daily_from_dict({"wake_time": bad})

    def test_runtime_flags_are_booleans_not_truthiness(self) -> None:
        base = {"timestamp": "2026-05-17T10:00:00"}
        for good, want in (
            (True, True),
            (False, False),
            (1, True),
            (0, False),
            ("true", True),
            ("FALSE", False),
        ):
            data = {**base, "manual_lock_active": good}
            self.assertIs(load_runtime_from_dict(data).manual_lock_active, want, good)
        for bad in ("yes", "false-ish", "", 2, 0.5, None, [], {}, [0]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                load_runtime_from_dict({**base, "manual_lock_active": bad})

    def test_runtime_numbers_are_validated(self) -> None:
        base = {"timestamp": "2026-05-17T10:00:00"}
        for field in ("accumulated_seconds", "cumulative_extension_seconds"):
            for bad in (None, True, "x", -1, [], {}):
                with self.assertRaises(ValueError, msg=f"{field}={bad!r}"):
                    load_runtime_from_dict({**base, field: bad})
        with self.assertRaises(ValueError):
            load_runtime_from_dict({**base, "cumulative_extension_seconds": 30.9})
        self.assertEqual(
            load_runtime_from_dict({**base, "accumulated_seconds": "12.5"}).accumulated_seconds,
            12.5,
        )

    def test_timestamp_drops_the_offset_and_rejects_odd_formats(self) -> None:
        for text in ("2026-05-17T10:00:00+02:00", "2026-05-17T10:00:00Z", "2026-05-17 10:00:00"):
            runtime = load_runtime_from_dict({"timestamp": text})
            self.assertEqual(runtime.timestamp, datetime(2026, 5, 17, 10, 0, 0), text)
            self.assertIsNone(runtime.timestamp.tzinfo)
        for text in (
            "20260517T100000",
            "2026-W20-7",
            "2026-05-17x10:00",
            "2026-05-17Z",
            "١٢٣٤-05-17",
        ):
            with self.assertRaises(ValueError, msg=text):
                load_runtime_from_dict({"timestamp": text})

    def test_complete_daily_dict_needs_real_values(self) -> None:
        full = {"wake_time": "07:00", "bed_time": "21:00", "allowance": 60}
        self.assertTrue(is_complete_daily_dict(full))
        for override in (
            {"allowance": True},
            {"allowance": 0},
            {"allowance": 0.5},
            {"bed_time": 2100},
            {"wake_time": ""},
        ):
            self.assertFalse(is_complete_daily_dict({**full, **override}), override)


class StoreRecoveryTests(unittest.TestCase):
    NOW = datetime(2026, 5, 17, 10, 0, 0)
    DAILY = {"wake_time": "07:00", "bed_time": "21:00", "allowance": 120}
    STATE = {
        "timestamp": "2026-05-17T09:00:00",
        "accumulated_seconds": 600.5,
        "manual_lock_active": True,
        "cumulative_extension_seconds": 900,
    }

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.store = AgentStateStore(
            self.dir, current_user="kid", clock=lambda: self.NOW, program_data_dir=None
        )

    def write(self, name: str, content: object) -> None:
        text = content if isinstance(content, str) else json.dumps(content)
        (self.dir / name).write_text(text, encoding="utf-8")

    def corrupt_files(self) -> list[str]:
        return sorted(p.name for p in self.dir.glob("*.corrupt-*"))

    def test_corrupt_state_is_quarantined_and_backup_restored(self) -> None:
        self.write("daily_settings.json", self.DAILY)
        self.write("state.json", "{broken")
        self.write("state.json.bak", self.STATE)
        _daily, runtime = self.store.load()
        self.assertAlmostEqual(runtime.accumulated_seconds, 600.5)
        self.assertEqual(self.corrupt_files(), ["state.json.corrupt-20260517T100000"])
        self.assertEqual(
            json.loads((self.dir / "state.json").read_text())["manual_lock_active"], True
        )
        self.assertEqual(
            [(p.file, p.action) for p in self.store.problems],
            [("state.json", "quarantined"), ("state.json", "restored_from_backup")],
        )

    def test_deleted_state_is_restored_from_backup(self) -> None:
        self.write("daily_settings.json", self.DAILY)
        self.write("state.json.bak", self.STATE)
        _daily, runtime = self.store.load()
        self.assertAlmostEqual(runtime.accumulated_seconds, 600.5)
        self.assertEqual(self.corrupt_files(), [])
        self.assertTrue((self.dir / "state.json").exists())

    def test_save_keeps_the_previous_good_file_as_backup(self) -> None:
        daily, runtime = DailySettings(None, dtime(7, 0), 60), RuntimeState(self.NOW, 5.0, False, 0)
        self.store.save(daily, runtime)
        self.assertFalse((self.dir / "state.json.bak").exists())
        runtime.accumulated_seconds = 99.0
        self.store.save(daily, runtime)
        self.assertEqual(
            json.loads((self.dir / "state.json.bak").read_text())["accumulated_seconds"], 5.0
        )

    def test_corrupt_file_is_not_copied_over_the_backup(self) -> None:
        daily, runtime = DailySettings(None, dtime(7, 0), 60), RuntimeState(self.NOW, 5.0, False, 0)
        self.store.save(daily, runtime)
        runtime.accumulated_seconds = 6.0
        self.store.save(daily, runtime)  # bak = 5.0
        self.write("state.json", "garbage")
        self.store.save(daily, runtime)  # must not promote "garbage" to the backup
        self.assertEqual(
            json.loads((self.dir / "state.json.bak").read_text())["accumulated_seconds"], 5.0
        )

    def test_unusable_settings_are_kept_aside_and_defaults_used(self) -> None:
        self.write("daily_settings.json", {"allowance": True})
        self.write("state.json", self.STATE)
        daily, runtime = self.store.load()
        self.assertIsNone(daily.allowance)
        self.assertEqual(self.corrupt_files(), ["daily_settings.json.corrupt-20260517T100000"])
        # The runtime that was perfectly good is untouched.
        self.assertAlmostEqual(runtime.accumulated_seconds, 600.5)
        self.assertEqual(json.loads((self.dir / "state.json").read_text()), self.STATE)

    def test_byte_order_mark_and_non_objects(self) -> None:
        self.write("daily_settings.json", "\ufeff" + json.dumps(self.DAILY))
        self.write("state.json", "[1, 2]")
        daily, _runtime = self.store.load()
        self.assertEqual(daily.allowance, 120)
        self.assertEqual(self.corrupt_files(), ["state.json.corrupt-20260517T100000"])

    def test_nan_is_not_a_number(self) -> None:
        self.write("daily_settings.json", self.DAILY)
        self.write("state.json", '{"timestamp": "2026-05-17T09:00:00", "accumulated_seconds": NaN}')
        _daily, runtime = self.store.load()
        self.assertEqual(runtime.accumulated_seconds, 0.0)
        self.assertEqual(self.corrupt_files(), ["state.json.corrupt-20260517T100000"])

    def test_null_number_no_longer_aborts_the_load(self) -> None:
        self.write("daily_settings.json", self.DAILY)
        self.write("state.json", {**self.STATE, "cumulative_extension_seconds": None})
        _daily, runtime = self.store.load()
        self.assertEqual(runtime.cumulative_extension_seconds, 0)
        self.assertEqual(len(self.corrupt_files()), 1)

    def test_legacy_state_does_not_overwrite_existing_settings(self) -> None:
        self.write("daily_settings.json", self.DAILY)
        self.write("pc_control_state.json", {"usage_allowance": 15, "wake_time": "05:00"})
        daily, runtime = self.store.load()
        self.assertEqual((daily.allowance, daily.wake_time), (120, dtime(7, 0)))
        self.assertEqual(
            json.loads((self.dir / "daily_settings.json").read_text())["allowance"], 120
        )
        self.assertEqual(runtime.accumulated_seconds, 0.0)

    def test_unusable_legacy_state_is_ignored_not_fatal(self) -> None:
        self.write("pc_control_state.json", {"wake_time": "bad"})
        daily, _runtime = self.store.load()
        self.assertEqual(daily.wake_time, dtime(7, 0))
        self.assertEqual(
            [(p.file, p.action) for p in self.store.problems],
            [("pc_control_state.json", "ignored")],
        )

    def test_unreadable_file_is_an_error_not_a_verdict(self) -> None:
        self.write("daily_settings.json", self.DAILY)
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("locked")):
            with self.assertRaises(OSError):
                self.store.load()
        self.assertEqual(self.corrupt_files(), [])


if __name__ == "__main__":
    unittest.main()

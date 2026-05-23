"""Tests for agent_state persistence and migration."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, time as dtime
from pathlib import Path

from kid_pc_monitor.agent_state import (
    AgentStateStore,
    DefaultValues,
    RuntimeState,
    effective_daily_limit_minutes,
    migrate_legacy_state,
    reset_runtime_for_new_period,
    runtime_state_is_current,
)


class AgentStateTests(unittest.TestCase):
    def test_effective_daily_limit_includes_extensions(self) -> None:
        defaults = DefaultValues(bed_time=None, wake_time=dtime(7, 0), daily_limit=120)
        runtime = RuntimeState(
            timestamp=datetime.now(),
            accumulated_seconds=0,
            manual_lock_active=False,
            cumulative_extension_seconds=1800,
        )
        self.assertEqual(effective_daily_limit_minutes(defaults, runtime), 150)

    def test_effective_daily_limit_none_without_base_or_extension(self) -> None:
        defaults = DefaultValues(bed_time=None, wake_time=dtime(7, 0), daily_limit=None)
        runtime = RuntimeState(
            timestamp=datetime.now(),
            accumulated_seconds=0,
            manual_lock_active=False,
            cumulative_extension_seconds=0,
        )
        self.assertIsNone(effective_daily_limit_minutes(defaults, runtime))

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
                        "usage_limit": 90,
                        "manual_lock_active": True,
                        "accumulated_seconds": 120,
                        "accumulated_date": datetime.now().date().isoformat(),
                    }
                ),
                encoding="utf-8",
            )
            migrated = migrate_legacy_state(legacy, current_user="kid")
            assert migrated is not None
            defaults, runtime = migrated
            self.assertEqual(defaults.bed_time, dtime(21, 0))
            self.assertEqual(defaults.wake_time, dtime(8, 30))
            self.assertEqual(defaults.daily_limit, 90)
            self.assertTrue(runtime.manual_lock_active)
            self.assertAlmostEqual(runtime.accumulated_seconds, 120.0)

    def test_store_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AgentStateStore(Path(tmp), current_user="kid")
            defaults = DefaultValues(
                bed_time=dtime(21, 0),
                wake_time=dtime(7, 0),
                daily_limit=120,
            )
            runtime = RuntimeState(
                timestamp=datetime.now(),
                accumulated_seconds=300,
                manual_lock_active=False,
                cumulative_extension_seconds=900,
            )
            store.save(defaults, runtime)
            loaded_defaults, loaded_runtime = store.load()
            self.assertEqual(loaded_defaults.bed_time, dtime(21, 0))
            self.assertEqual(loaded_defaults.daily_limit, 120)
            self.assertAlmostEqual(loaded_runtime.accumulated_seconds, 300.0)
            self.assertEqual(loaded_runtime.cumulative_extension_seconds, 900)

    def test_store_resets_stale_runtime_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            defaults_path = data_dir / "default_values.json"
            state_path = data_dir / "state.json"
            defaults_path.write_text(
                json.dumps({"wake_time": "07:00", "bed_time": None, "daily_limit": 60}),
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
            _defaults, runtime = store.load()
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


if __name__ == "__main__":
    unittest.main()

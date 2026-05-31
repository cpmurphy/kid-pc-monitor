"""Tests for installer daily-settings reuse detection."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import time as dtime
from pathlib import Path

from kid_pc_monitor.agent_state import (
    DailySettings,
    find_complete_daily_settings,
    is_complete_daily_dict,
)


class InstallDailyReuseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _write_daily(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_is_complete_daily_dict_accepts_full_schedule(self) -> None:
        data = {"wake_time": "07:00", "bed_time": "21:00", "allowance": 90}
        self.assertTrue(is_complete_daily_dict(data))

    def test_is_complete_daily_dict_rejects_null_allowance(self) -> None:
        data = {"wake_time": "07:00", "bed_time": "21:00", "allowance": None}
        self.assertFalse(is_complete_daily_dict(data))

    def test_is_complete_daily_dict_rejects_missing_allowance(self) -> None:
        data = {"wake_time": "07:00", "bed_time": "21:00"}
        self.assertFalse(is_complete_daily_dict(data))

    def test_is_complete_daily_dict_rejects_non_positive_allowance(self) -> None:
        data = {"wake_time": "07:00", "bed_time": "21:00", "allowance": 0}
        self.assertFalse(is_complete_daily_dict(data))

    def test_is_complete_daily_dict_rejects_missing_bed_time(self) -> None:
        data = {"wake_time": "07:00", "bed_time": None, "allowance": 60}
        self.assertFalse(is_complete_daily_dict(data))

    def test_is_complete_daily_dict_rejects_invalid_time(self) -> None:
        data = {"wake_time": "25:00", "bed_time": "21:00", "allowance": 60}
        self.assertFalse(is_complete_daily_dict(data))

    def test_find_complete_daily_settings_from_profile(self) -> None:
        profile = self.root / "profile" / "daily_settings.json"
        program_data = self.root / "programdata" / "daily_settings.json"
        self._write_daily(
            profile,
            {"wake_time": "06:30", "bed_time": "20:30", "allowance": 45},
        )

        result = find_complete_daily_settings(
            profile_path=profile,
            program_data_path=program_data,
        )

        self.assertIsNotNone(result)
        daily, source = result
        self.assertEqual(source, profile)
        self.assertEqual(daily, DailySettings(
            bed_time=dtime(20, 30),
            wake_time=dtime(6, 30),
            allowance=45,
        ))

    def test_find_complete_daily_settings_prefers_profile_over_program_data(self) -> None:
        profile = self.root / "profile" / "daily_settings.json"
        program_data = self.root / "programdata" / "daily_settings.json"
        self._write_daily(
            profile,
            {"wake_time": "06:30", "bed_time": "20:30", "allowance": 45},
        )
        self._write_daily(
            program_data,
            {"wake_time": "08:00", "bed_time": "22:00", "allowance": 120},
        )

        result = find_complete_daily_settings(
            profile_path=profile,
            program_data_path=program_data,
        )

        self.assertIsNotNone(result)
        _, source = result
        self.assertEqual(source, profile)

    def test_find_complete_daily_settings_falls_back_to_program_data(self) -> None:
        profile = self.root / "profile" / "daily_settings.json"
        program_data = self.root / "programdata" / "daily_settings.json"
        self._write_daily(
            program_data,
            {"wake_time": "08:00", "bed_time": "22:00", "allowance": 120},
        )

        result = find_complete_daily_settings(
            profile_path=profile,
            program_data_path=program_data,
        )

        self.assertIsNotNone(result)
        daily, source = result
        self.assertEqual(source, program_data)
        self.assertEqual(daily.allowance, 120)

    def test_find_complete_daily_settings_returns_none_when_incomplete(self) -> None:
        profile = self.root / "profile" / "daily_settings.json"
        program_data = self.root / "programdata" / "daily_settings.json"
        self._write_daily(
            profile,
            {"wake_time": "07:00", "bed_time": "21:00", "allowance": None},
        )

        result = find_complete_daily_settings(
            profile_path=profile,
            program_data_path=program_data,
        )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()

"""Tests for the web panel's injectable clock (used by the Go port's vectors)."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_poller, panel_clock, panel_db, scan_store, snapshot_store

TZ = timezone(timedelta(hours=-5))
FIXED = datetime(2026, 3, 7, 21, 15, 42, 123456, tzinfo=TZ)


class PanelClockTests(unittest.TestCase):
    def test_default_is_aware_local_time(self) -> None:
        self.assertIsNotNone(panel_clock.now().tzinfo)

    def test_fixed_clock_and_timezone(self) -> None:
        with panel_clock.fixed(lambda: FIXED, tz=TZ):
            self.assertEqual(panel_clock.now(), FIXED)
            naive = datetime(2026, 1, 2, 3, 4, 5)
            self.assertEqual(panel_clock.localize(naive), naive.replace(tzinfo=TZ))
            utc = datetime(2026, 1, 2, 8, 0, tzinfo=UTC)
            self.assertEqual(panel_clock.localize(utc).utcoffset(), timedelta(hours=-5))
        self.assertNotEqual(panel_clock.now(), FIXED)

    def test_clock_is_converted_to_fixed_timezone(self) -> None:
        with panel_clock.fixed(lambda: FIXED.astimezone(UTC), tz=TZ):
            self.assertEqual(panel_clock.now().isoformat(), FIXED.isoformat())

    def test_seed_makes_jitter_repeatable(self) -> None:
        with panel_clock.fixed(seed=7):
            first = [agent_poller._cycle_sleep_sec(60.0) for _ in range(3)]
        with panel_clock.fixed(seed=7):
            second = [agent_poller._cycle_sleep_sec(60.0) for _ in range(3)]
        self.assertEqual(first, second)
        self.assertTrue(all(55.0 <= v <= 65.0 for v in first))


class StoresUsePanelClockTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_snapshot_and_registry_timestamps_follow_fixed_clock(self) -> None:
        pc_info = {
            "ip": "10.0.0.5",
            "hostname": "KidPC",
            "status": "UNLOCKED",
            "current_user": "child",
            "reachable": True,
        }
        with panel_clock.fixed(lambda: FIXED, tz=TZ):
            scan_store.record_poll_inspect("10.0.0.5", pc_info)
            snapshot_store.save_snapshot(pc_info)
            updated = scan_store.get_pc_poll_updated_at("10.0.0.5")
            snapshot = snapshot_store.get_latest_snapshot_for_pc(ip="10.0.0.5")

        self.assertEqual(updated, FIXED.replace(microsecond=0))
        assert snapshot is not None
        self.assertEqual(snapshot[0], "2026-03-07T21:15:42-05:00")


if __name__ == "__main__":
    unittest.main()

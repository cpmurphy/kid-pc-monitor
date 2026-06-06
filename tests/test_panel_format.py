"""Tests for panel display formatting helpers."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from kid_pc_monitor.panel_format import format_snapshot_recorded_at


class FormatSnapshotRecordedAtTests(unittest.TestCase):
    _TZ = timezone(timedelta(hours=-5))
    _NOW = datetime(2026, 6, 5, 18, 0, 0, tzinfo=_TZ)

    def test_today_shows_compact_local_time(self) -> None:
        self.assertEqual(
            format_snapshot_recorded_at(
                "2026-06-05T14:16:54-05:00",
                now=self._NOW,
            ),
            "2:16pm",
        )

    def test_today_morning_shows_am(self) -> None:
        self.assertEqual(
            format_snapshot_recorded_at(
                "2026-06-05T09:05:00-05:00",
                now=self._NOW,
            ),
            "9:05am",
        )

    def test_yesterday(self) -> None:
        self.assertEqual(
            format_snapshot_recorded_at(
                "2026-06-04T14:16:54-05:00",
                now=self._NOW,
            ),
            "2:16pm yesterday",
        )

    def test_older_date_shows_short_month_and_day(self) -> None:
        self.assertEqual(
            format_snapshot_recorded_at(
                "2026-06-01T14:16:54-05:00",
                now=self._NOW,
            ),
            "2:16pm Jun 1",
        )

    def test_invalid_timestamp_is_returned_unchanged(self) -> None:
        self.assertEqual(format_snapshot_recorded_at("not-a-date"), "not-a-date")


if __name__ == "__main__":
    unittest.main()

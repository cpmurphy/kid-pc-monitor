"""Tests for panel display formatting helpers."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from kid_pc_monitor.panel_format import (
    format_snapshot_recorded_at,
    format_usage_date,
    parse_remaining_minutes,
)


class FormatSnapshotRecordedAtTests(unittest.TestCase):
    _TZ = timezone(timedelta(hours=-5))
    _NOW = datetime(2026, 6, 5, 18, 0, 0, tzinfo=_TZ)

    def test_today_shows_compact_local_time(self) -> None:
        self.assertEqual(
            format_snapshot_recorded_at(
                "2026-06-05T15:30:00-05:00",
                now=self._NOW,
            ),
            "3:30pm",
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
                "2026-06-04T15:30:00-05:00",
                now=self._NOW,
            ),
            "3:30pm yesterday",
        )

    def test_older_date_shows_short_month_and_day(self) -> None:
        self.assertEqual(
            format_snapshot_recorded_at(
                "2026-06-01T15:30:00-05:00",
                now=self._NOW,
            ),
            "3:30pm Jun 1",
        )

    def test_invalid_timestamp_is_returned_unchanged(self) -> None:
        self.assertEqual(format_snapshot_recorded_at("not-a-date"), "not-a-date")


if __name__ == "__main__":
    unittest.main()


class FormatUsageDateTests(unittest.TestCase):
    def test_short_weekday_without_year(self) -> None:
        self.assertEqual(format_usage_date("2026-10-19"), "Mon Oct 19")

    def test_single_digit_day_not_padded(self) -> None:
        self.assertEqual(format_usage_date("2026-10-06"), "Tue Oct 6")

    def test_invalid_date_passes_through(self) -> None:
        self.assertEqual(format_usage_date("not-a-date"), "not-a-date")


class ParseRemainingMinutesTests(unittest.TestCase):
    def test_minutes_text(self) -> None:
        self.assertEqual(parse_remaining_minutes("90 minutes"), 90)

    def test_number(self) -> None:
        self.assertEqual(parse_remaining_minutes(45), 45)

    def test_unparseable_values(self) -> None:
        self.assertIsNone(parse_remaining_minutes(None))
        self.assertIsNone(parse_remaining_minutes("No limits set"))
        self.assertIsNone(parse_remaining_minutes(True))

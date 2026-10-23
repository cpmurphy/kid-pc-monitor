"""Human-friendly display formatting for the parent web panel."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta


def format_minutes_duration(minutes: int | float | None) -> str:
    """Format a minute count as H:MM or 'Not set'."""
    if minutes is None:
        return "Not set"
    total = int(round(minutes))
    hours, mins = divmod(total, 60)
    if hours:
        return f"{hours}:{mins:02d}"
    return f"{mins} min"


def format_seconds_duration(seconds: int | float) -> str:
    return format_minutes_duration(seconds / 60)


def format_usage_date(day: str) -> str:
    """Format an ISO calendar date as a short weekday + date, e.g. 'Mon Oct 20'."""
    try:
        parsed = date.fromisoformat(day)
    except ValueError:
        return day
    return f"{parsed.strftime('%a %b')} {parsed.day}"


_REMAINING_MINUTES_RE = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*(?:min(?:ute)?s?)?\s*$")


def parse_remaining_minutes(value: object) -> float | None:
    """Return minutes from a ``time_remaining`` value (number or 'N minutes' text)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        match = _REMAINING_MINUTES_RE.match(value)
        if match:
            return float(match.group(1))
    return None


def _format_compact_clock_time(dt: datetime) -> str:
    """Format a datetime as a compact 12-hour clock string, e.g. 2:16pm."""
    hour = dt.hour % 12 or 12
    suffix = "am" if dt.hour < 12 else "pm"
    return f"{hour}:{dt.minute:02d}{suffix}"


def format_snapshot_recorded_at(
    recorded_at: str | None,
    *,
    now: datetime | None = None,
) -> str:
    """Format a snapshot ISO timestamp for parent-facing UI.

    Times are shown in the timezone of ``now`` (panel-local when omitted), so
    injected ``now`` values make tests independent of the host timezone.
    """
    if not recorded_at:
        return ""
    try:
        dt = datetime.fromisoformat(recorded_at)
    except ValueError:
        return recorded_at
    reference = now if now is not None else datetime.now().astimezone()
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=datetime.now().astimezone().tzinfo)
    display_tz = reference.tzinfo
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=display_tz)
    local_dt = dt.astimezone(display_tz)
    reference = reference.astimezone(display_tz)
    snapshot_day = local_dt.date()
    today = reference.date()
    time_str = _format_compact_clock_time(local_dt)
    if snapshot_day == today:
        return time_str
    if snapshot_day == today - timedelta(days=1):
        return f"{time_str} yesterday"
    return f"{time_str} {local_dt.strftime('%b')} {local_dt.day}"

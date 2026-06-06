"""Human-friendly display formatting for the parent web panel."""

from __future__ import annotations

from datetime import datetime, timedelta


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
    """Format a snapshot ISO timestamp for parent-facing UI."""
    if not recorded_at:
        return ""
    try:
        dt = datetime.fromisoformat(recorded_at)
    except ValueError:
        return recorded_at
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    local_dt = dt.astimezone()
    reference = (now or datetime.now().astimezone()).astimezone()
    snapshot_day = local_dt.date()
    today = reference.date()
    time_str = _format_compact_clock_time(local_dt)
    if snapshot_day == today:
        return time_str
    if snapshot_day == today - timedelta(days=1):
        return f"{time_str} yesterday"
    return f"{time_str} {local_dt.strftime('%b')} {local_dt.day}"

"""Pure lock policy helpers for the Kid PC Monitor agent.

This module intentionally has no Windows, tkinter, socket, or filesystem
dependencies so it can be unit-tested on any development machine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time as dtime, timedelta

# Default morning unlock when wake_time is not configured (e.g. legacy state files).
DEFAULT_WAKE_TIME = dtime(7, 0)


@dataclass(frozen=True)
class LockDecision:
    should_lock: bool
    reason: str = ""


def should_monitor_user(
    current_user: str,
    monitored_users: list[str] | tuple[str, ...] | None = None,
    exempt_users: list[str] | tuple[str, ...] | None = None,
) -> bool:
    """Return whether restrictions apply to current_user."""
    monitored_users = monitored_users or []
    exempt_users = exempt_users or []

    if monitored_users:
        return current_user in monitored_users

    if exempt_users:
        return current_user not in exempt_users

    return True


def parse_time_hhmm(value: str) -> dtime:
    """Parse HH:MM or H:MM into a time; raises ValueError if invalid."""
    parts = value.strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid time '{value}'; use HH:MM")
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"Invalid time '{value}'; hour/minute out of range")
    return dtime(hour, minute)


def _minutes_since_midnight(when: dtime) -> int:
    return when.hour * 60 + when.minute


def usage_period_date(now: datetime, wake_time: dtime = DEFAULT_WAKE_TIME) -> date:
    """
    Label for the current daily usage period.

    The period starts at wake_time each day (not midnight), so early-morning
    use before wake still counts toward the previous day's allowance.
    """
    if (now.hour, now.minute) < (wake_time.hour, wake_time.minute):
        return now.date() - timedelta(days=1)
    return now.date()


def is_in_bedtime_curfew(
    now: datetime,
    lock_time: dtime,
    wake_time: dtime = DEFAULT_WAKE_TIME,
) -> bool:
    """
    True when now is in the overnight curfew from lock_time until wake_time.

    Typical case: bedtime 21:00, wake 07:00 — locked from 21:00 through 06:59.
    """
    now_m = now.hour * 60 + now.minute
    lock_m = _minutes_since_midnight(lock_time)
    wake_m = _minutes_since_midnight(wake_time)
    if lock_m == wake_m:
        return False
    if lock_m > wake_m:
        return now_m >= lock_m or now_m < wake_m
    return lock_m <= now_m < wake_m


def lock_decision(
    *,
    now: datetime,
    lock_times: list[dtime] | tuple[dtime, ...],
    usage_limit: int | None,
    accumulated_minutes: float,
    monitor_user: bool = True,
    manual_lock_active: bool = False,
    wake_time: dtime = DEFAULT_WAKE_TIME,
) -> LockDecision:
    """
    Decide whether the agent should enforce a lock at now.

    Scheduled lock times start a curfew that lasts until wake_time (not midnight).
    Usage limits lock once accumulated_minutes for the current wake-to-wake period
    reaches the limit.
    """
    if not monitor_user:
        return LockDecision(False)

    if manual_lock_active:
        return LockDecision(True, "Manual lock requested")

    for lock_time in lock_times:
        if is_in_bedtime_curfew(now, lock_time, wake_time):
            if (now.hour, now.minute) < (wake_time.hour, wake_time.minute):
                return LockDecision(
                    True,
                    f"Before wake-up time {wake_time.hour:02d}:{wake_time.minute:02d}",
                )
            return LockDecision(
                True,
                f"Past scheduled lock time {lock_time.hour:02d}:{lock_time.minute:02d}",
            )

    if usage_limit and accumulated_minutes >= usage_limit:
        return LockDecision(
            True,
            f"Usage limit of {usage_limit} minutes reached",
        )

    return LockDecision(False)


def minutes_until_lock(
    *,
    now: datetime,
    lock_times: list[dtime] | tuple[dtime, ...],
    usage_limit: int | None,
    accumulated_minutes: float,
    monitor_user: bool = True,
    manual_lock_active: bool = False,
    wake_time: dtime = DEFAULT_WAKE_TIME,
) -> float | None:
    """Return minutes until the next lock, 0 if already locked, or None."""
    if not monitor_user:
        return None

    if lock_decision(
        now=now,
        lock_times=lock_times,
        usage_limit=usage_limit,
        accumulated_minutes=accumulated_minutes,
        monitor_user=monitor_user,
        manual_lock_active=manual_lock_active,
        wake_time=wake_time,
    ).should_lock:
        return 0

    min_remaining = None

    for lock_time in lock_times:
        lock_datetime = now.replace(
            hour=lock_time.hour,
            minute=lock_time.minute,
            second=0,
            microsecond=0,
        )

        if lock_datetime <= now:
            lock_datetime = lock_datetime + timedelta(days=1)

        minutes_remaining = (lock_datetime - now).total_seconds() / 60
        if min_remaining is None or minutes_remaining < min_remaining:
            min_remaining = minutes_remaining

    if usage_limit:
        minutes_remaining = usage_limit - accumulated_minutes
        if min_remaining is None or minutes_remaining < min_remaining:
            min_remaining = minutes_remaining

    return min_remaining

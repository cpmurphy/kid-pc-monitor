"""Pure lock policy helpers for the Kid PC Monitor agent.

This module intentionally has no Windows, tkinter, socket, or filesystem
dependencies so it can be unit-tested on any development machine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time as dtime, timedelta


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


def lock_decision(
    *,
    now: datetime,
    lock_times: list[dtime] | tuple[dtime, ...],
    usage_limit: int | None,
    start_time: datetime,
    monitor_user: bool = True,
    manual_lock_active: bool = False,
) -> LockDecision:
    """
    Decide whether the agent should enforce a lock at now.

    Scheduled lock times are daily bedtime starts: once the local clock reaches
    a configured time, the user stays locked until local midnight. Usage limits
    lock once elapsed minutes for the current start_time reach the limit.
    """
    if not monitor_user:
        return LockDecision(False)

    if manual_lock_active:
        return LockDecision(True, "Manual lock requested")

    for lock_time in lock_times:
        if (now.hour, now.minute) >= (lock_time.hour, lock_time.minute):
            return LockDecision(
                True,
                f"Past scheduled lock time {lock_time.hour:02d}:{lock_time.minute:02d}",
            )

    if usage_limit:
        usage_minutes = (now - start_time).total_seconds() / 60
        if usage_minutes >= usage_limit:
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
    start_time: datetime,
    monitor_user: bool = True,
    manual_lock_active: bool = False,
) -> float | None:
    """Return minutes until the next lock, 0 if already locked, or None."""
    if not monitor_user:
        return None

    if lock_decision(
        now=now,
        lock_times=lock_times,
        usage_limit=usage_limit,
        start_time=start_time,
        monitor_user=monitor_user,
        manual_lock_active=manual_lock_active,
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
        usage_minutes = (now - start_time).total_seconds() / 60
        minutes_remaining = usage_limit - usage_minutes
        if min_remaining is None or minutes_remaining < min_remaining:
            min_remaining = minutes_remaining

    return min_remaining

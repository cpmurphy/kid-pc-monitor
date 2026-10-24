"""Daily time limits, bedtime enforcement, and parent actions for the kid agent."""

from __future__ import annotations

import getpass
import logging
import math
import os
import threading
import time
from collections.abc import Callable
from datetime import datetime
from datetime import time as dtime
from pathlib import Path

from kid_pc_monitor.agent_state import (
    PLATFORM_DEFAULT,
    AgentStateStore,
    DailySettings,
    ProgramDataDir,
    RuntimeState,
    effective_daily_allowance_minutes,
    reset_runtime_for_new_period,
    reset_runtime_if_needed,
)
from kid_pc_monitor.host_platform import HostPlatform, get_default_platform
from kid_pc_monitor.lock_policy import (
    DEFAULT_WAKE_TIME,
    enforcement_state,
    format_access_status,
    lock_decision,
    minutes_until_lock,
    should_monitor_user,
    usage_period_date,
)

# ============================================
# CONFIGURATION
# ============================================

# List of Windows usernames to monitor (leave empty to monitor all users)
# Example: MONITORED_USERS = ['Tommy', 'Sarah', 'kid1']
MONITORED_USERS: list[str] = []

# List of Windows usernames to EXEMPT from monitoring (parents/admins)
# Example: EXEMPT_USERS = ['pavel', 'Mom', 'Dad', 'Administrator']
EXEMPT_USERS: list[str] = []

# If both lists are empty, ALL users will be monitored
# If MONITORED_USERS has entries, ONLY those users are monitored
# If EXEMPT_USERS has entries, everyone EXCEPT those users is monitored

# Morning unlock for bedtime curfews and daily usage reset (HH:MM local time).
# Overridden by wake_time in pc_control_state.json (set at install).
DEFAULT_WAKE_UP_TIME = DEFAULT_WAKE_TIME

# Seconds between state saves from the monitoring loop.
PERSIST_INTERVAL_SECONDS = 60

# Per-user data directory for agent state (and pc_control.log when used by the agent).
data_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "KidPCMonitor"
data_dir.mkdir(parents=True, exist_ok=True)


def _system_clock() -> datetime:
    return datetime.now()


class PCTimeControl:
    def __init__(
        self,
        platform: HostPlatform | None = None,
        *,
        monitored_users: list[str] | None = None,
        exempt_users: list[str] | None = None,
        data_directory: Path | None = None,
        start_background_threads: bool = True,
        clock: Callable[[], datetime] | None = None,
        current_user: str | None = None,
        program_data_dir: ProgramDataDir = PLATFORM_DEFAULT,
    ):
        self.clock = clock or _system_clock
        self.platform = platform or get_default_platform()
        self.monitored_users = MONITORED_USERS if monitored_users is None else monitored_users
        self.exempt_users = EXEMPT_USERS if exempt_users is None else exempt_users

        self.daily = DailySettings(
            bed_time=None,
            wake_time=DEFAULT_WAKE_UP_TIME,
            allowance=None,
        )
        self.runtime = RuntimeState(
            timestamp=self.clock(),
            accumulated_seconds=0.0,
            manual_lock_active=False,
            cumulative_extension_seconds=0,
        )
        # Wall-clock of the most recent observed active+unlocked tick, or None
        # if the previous tick was paused. Used to credit elapsed seconds
        # between consecutive active ticks while ignoring paused gaps.
        self.last_tick_at = None
        # Throttle for periodic save_state() calls inside run_monitor.
        self.last_persist_at = None
        self.is_locked = False
        self.last_activity = self.clock()
        self.current_user = current_user if current_user is not None else getpass.getuser()
        base_dir = data_directory or data_dir
        base_dir.mkdir(parents=True, exist_ok=True)
        self.agent_log_path = base_dir / "pc_control.log"
        self.state_store = AgentStateStore(
            base_dir,
            current_user=self.current_user,
            clock=self.clock,
            program_data_dir=program_data_dir,
        )
        self.logger = logging.getLogger("PCTimeControl")
        self.warnings_sent = set()  # Track which warnings have been sent
        self.warning_intervals = [30, 15, 5, 1]  # Warning times in minutes before lock
        self.warnings_date = None
        # Reason of the last "Locking PC" log line, so a lock window logs once.
        self.last_logged_reason: str | None = None
        # Monitor-step phases that are failing, by name, with the last error text.
        self.step_errors: dict[str, str] = {}

        # Log which user we're running as
        if self.should_monitor_user():
            self.logger.info(f"Monitoring enabled for user: {self.current_user}")
            print(f"[{self.clock():%H:%M:%S}] Monitoring user: {self.current_user}")
        else:
            self.logger.info(f"User {self.current_user} is EXEMPT from monitoring")
            print(
                f"[{self.clock():%H:%M:%S}] User {self.current_user} is EXEMPT - no restrictions will apply"
            )

        # Set when the state files could not be read at all (an I/O error, not bad
        # content).  Saving is then skipped so defaults never replace the real files.
        self.state_load_failed = False

        # Load previous state if exists
        self.load_state()
        self.warnings_date = usage_period_date(self.clock(), self.daily.wake_time)

        if start_background_threads:
            self.monitor_thread = threading.Thread(target=self.monitor_activity, daemon=True)
            self.monitor_thread.start()
        else:
            self.monitor_thread = None

    def should_monitor_user(self):
        """Check if current user should be monitored based on configuration"""
        return should_monitor_user(self.current_user, self.monitored_users, self.exempt_users)

    def load_state(self):
        """Load saved daily settings and runtime state from JSON files."""
        try:
            self.daily, self.runtime = self.state_store.load()
            self.state_load_failed = False
            for problem in self.state_store.problems:
                self.logger.error(
                    "State file problem: %s %s (%s)",
                    problem.file,
                    problem.action.replace("_", " "),
                    problem.reason,
                )
            bed_label = (
                f"{self.daily.bed_time.hour:02d}:{self.daily.bed_time.minute:02d}"
                if self.daily.bed_time is not None
                else "none"
            )
            effective = effective_daily_allowance_minutes(self.daily, self.runtime)
            self.logger.info(
                "State applied: bed_time=%s wake_time=%02d:%02d daily_allowance=%s "
                "effective_allowance=%s manual_lock=%s accumulated_min=%.1f "
                "extension_sec=%d",
                bed_label,
                self.daily.wake_time.hour,
                self.daily.wake_time.minute,
                "none" if self.daily.allowance is None else f"{self.daily.allowance:d}",
                "none" if effective is None else f"{effective:.1f}",
                "true" if self.runtime.manual_lock_active else "false",
                self.runtime.accumulated_seconds / 60,
                self.runtime.cumulative_extension_seconds,
            )
            print(
                f"[{self.clock():%H:%M:%S}] Loaded settings from {self.state_store.data_directory}"
            )
        except Exception as e:
            self.state_load_failed = True
            self.logger.error("Error loading state: %s", e, exc_info=True)
            print(f"[{self.clock():%H:%M:%S}] Could not load previous state: {e}")

    def save_state(self):
        """Save daily settings and runtime state to JSON files."""
        if self.state_load_failed:
            # Retry the load: until it works, the in-memory defaults must not
            # overwrite whatever is on disk.
            self.load_state()
            if self.state_load_failed:
                self.logger.error("State files unreadable; not saving over them")
                return
        try:
            self.state_store.save(self.daily, self.runtime)
            self.logger.debug("State saved")
        except Exception as e:
            self.logger.error("Error saving state: %s", e, exc_info=True)

    def read_log_tail(self, *, tail: int) -> tuple[list[str], bool]:
        """Return up to ``tail`` lines from the end of the agent log and whether more exist."""
        path = self.agent_log_path
        if not path.is_file():
            return [], False
        with path.open("rb") as handle:
            handle.seek(0, 2)
            file_end = handle.tell()
            if file_end == 0:
                return [], False

            block = 8192
            remaining = file_end
            fragment = b""
            raw_lines: list[bytes] = []

            while remaining > 0 and len(raw_lines) <= tail:
                read_size = min(block, remaining)
                remaining -= read_size
                handle.seek(remaining)
                chunk = handle.read(read_size)
                fragment = chunk + fragment
                parts = fragment.split(b"\n")
                if remaining > 0:
                    fragment = parts[0]
                    parts = parts[1:]
                else:
                    fragment = b""
                for part in reversed(parts):
                    if part or raw_lines:
                        raw_lines.append(part)
                    if len(raw_lines) > tail:
                        break

            truncated = remaining > 0 or len(raw_lines) > tail
            if len(raw_lines) > tail:
                raw_lines = raw_lines[:tail]
            raw_lines.reverse()
            lines = [line.decode("utf-8", errors="replace") for line in raw_lines]

        return lines, truncated

    def _effective_usage_allowance_minutes(self) -> float | None:
        return effective_daily_allowance_minutes(self.daily, self.runtime)

    def _reset_runtime_if_needed(self, *, now: datetime | None = None) -> bool:
        now = now or self.clock()
        used_minutes = self.runtime.accumulated_seconds / 60
        extension_seconds = self.runtime.cumulative_extension_seconds
        if not reset_runtime_if_needed(self.runtime, self.daily.wake_time, now):
            return False
        self.logger.info(
            "Wake-time rollover (%02d:%02d): resetting daily runtime state "
            "(was %.1f min used, %s extension sec)",
            self.daily.wake_time.hour,
            self.daily.wake_time.minute,
            used_minutes,
            extension_seconds,
        )
        return True

    def check_if_locked(self) -> bool:
        """True when this session's workstation is locked (OS-specific).

        If the platform cannot say, assume it is not locked: enforcement then
        issues a lock instead of trusting a state it could not verify.
        """
        try:
            locked = self.platform.check_session_locked()
        except Exception as e:
            self._platform_query_failed("check_session_locked", e)
            return False
        self._note_recovered("check_session_locked")
        return locked

    def session_is_active(self) -> bool:
        """True when this session is the active console and not locked.

        If the platform cannot say, assume it is active: the time is counted
        rather than silently skipped.
        """
        try:
            active = self.platform.session_is_active()
        except Exception as e:
            self._platform_query_failed("session_is_active", e)
            return True
        self._note_recovered("session_is_active")
        return active

    def _platform_query_failed(self, name: str, error: Exception) -> None:
        self._note_failure(name, f"Platform {name} failed: {error}")

    def _note_failure(self, key: str, message: str) -> None:
        """Log a repeating failure once, until it changes or clears."""
        if self.step_errors.get(key) != message:
            self.step_errors[key] = message
            self.logger.error(message)

    def _note_recovered(self, key: str) -> None:
        if self.step_errors.pop(key, None) is not None:
            self.logger.info("%s recovered", key)

    def tick_accumulator(self):
        """
        Advance the active-use counter by the seconds elapsed since the last
        active tick. Reset at wake_time each day. Called once per second from
        run_monitor.
        """
        now = self.clock()

        if self._reset_runtime_if_needed(now=now):
            self.last_tick_at = None

        # Never credit usage while a lock window is active (bedtime curfew or
        # manual lock). Accurate session detection already covers this, but a
        # brief detection flicker during curfew must not inflate usage.
        in_lock_window, _ = self.currently_in_lock_window()

        if self.should_monitor_user() and self.session_is_active() and not in_lock_window:
            if self.last_tick_at is not None:
                delta = (now - self.last_tick_at).total_seconds()
                # Clamp to (0, 60): negative means clock went backwards;
                # >60 means the loop stalled or we resumed from sleep, in
                # which case we don't want to credit the whole gap.
                if 0 < delta < 60:
                    self.runtime.accumulated_seconds += delta
            self.last_tick_at = now
        else:
            self.last_tick_at = None

    def observe_lock_state(self) -> None:
        """Note lock/unlock transitions (console output only)."""
        actual_locked = self.check_if_locked()

        # Detect unlock
        if self.is_locked and not actual_locked:
            self.is_locked = False
            print(
                f"[{self.clock().strftime('%H:%M:%S')}] PC has been unlocked (detected by activity)"
            )

        # Detect manual lock (not by our script)
        elif not self.is_locked and actual_locked:
            print(f"[{self.clock().strftime('%H:%M:%S')}] PC has been locked (detected)")

    def monitor_activity(self):
        """Monitor lock/unlock status"""
        while True:
            self.observe_lock_state()
            time.sleep(3)  # Check every 3 seconds

    def set_bed_time(self, hour: int, minute: int) -> None:
        """Set the nightly bedtime curfew start."""
        self.daily.bed_time = dtime(hour, minute)
        self.logger.info("Parent action: bed time set to %02d:%02d", hour, minute)

    def clear_bed_time(self) -> None:
        self.daily.bed_time = None
        self.logger.info("Parent action: bed time cleared")

    def set_wake_time(self, hour: int, minute: int) -> None:
        """Set the daily morning unlock time (end of bedtime curfew)."""
        now = self.clock()
        previous_wake_time = self.daily.wake_time
        self.daily.wake_time = dtime(hour, minute)
        if usage_period_date(now, previous_wake_time) < usage_period_date(
            now, self.daily.wake_time
        ):
            used_minutes = self.runtime.accumulated_seconds / 60
            extension_seconds = self.runtime.cumulative_extension_seconds
            self.logger.info(
                "Wake-time change (%02d:%02d -> %02d:%02d): resetting daily runtime state "
                "(was %.1f min used, %s extension sec)",
                previous_wake_time.hour,
                previous_wake_time.minute,
                self.daily.wake_time.hour,
                self.daily.wake_time.minute,
                used_minutes,
                extension_seconds,
            )
            reset_runtime_for_new_period(self.runtime, now)
            self.last_tick_at = None
            self.warnings_sent.clear()
        self.warnings_date = usage_period_date(now, self.daily.wake_time)
        self.logger.info("Parent action: wake time set to %02d:%02d", hour, minute)

    def set_daily_allowance(self, minutes: int | None) -> None:
        """Set the default daily screen-time allowance in minutes."""
        self.daily.allowance = minutes
        if minutes is None:
            self.logger.info("Parent action: daily limit cleared")
        else:
            self.logger.info("Parent action: daily limit set to %d minutes", minutes)

    def extend_time(self, minutes: int) -> None:
        """Add temporary extra allowance for the current usage period."""
        self.runtime.cumulative_extension_seconds += minutes * 60
        self.runtime.manual_lock_active = False
        self.warnings_sent.clear()
        self.logger.info("Parent action: extended time by %d minutes", minutes)

    def clear_extensions(self) -> None:
        self.runtime.cumulative_extension_seconds = 0
        self.logger.info("Parent action: time extensions cleared")

    def show_message(self, message, title="PC Time Control"):
        """Display a message to the logged-in user (OS-specific UI)."""
        self.platform.show_message(message, title=title)

    def send_parent_message(self, message: str, title: str = "PC Time Control") -> None:
        """Show a parent-initiated popup and record it in the agent log."""
        preview = message if len(message) <= 120 else f"{message[:120]}..."
        self.logger.info("Parent action: message sent: %s", preview)
        self.show_message(message, title=title)

    def engage_manual_lock(self) -> None:
        """Enable manual lock enforcement and lock the workstation."""
        self.runtime.manual_lock_active = True
        self.lock_pc()
        self.logger.info("Parent action: manual lock engaged")

    def clear_manual_lock(self) -> None:
        """Clear manual lock enforcement."""
        self.runtime.manual_lock_active = False
        self.logger.info("Parent action: manual lock cleared")

    def lock_pc(self):
        """Lock the workstation for this session."""
        try:
            self.platform.lock_workstation()
            self.is_locked = True
        except Exception as e:
            self.logger.error(f"Error locking PC: {e}")
            print(f"[{self.clock():%H:%M:%S}] Error locking PC: {e}")

    def shutdown_pc(self, seconds=60):
        """Shutdown PC with warning."""
        try:
            self.platform.shutdown(seconds)
            self.logger.info("Parent action: shutdown in %ds", seconds)
        except Exception as e:
            self.logger.error(f"Error initiating shutdown: {e}")
            print(f"[{self.clock():%H:%M:%S}] Error shutting down: {e}")

    def cancel_shutdown(self):
        """Cancel pending shutdown."""
        self.platform.cancel_shutdown()

    def get_time_remaining(self):
        """Calculate minutes remaining until lock. Returns None if no allowance set."""
        return minutes_until_lock(
            now=self.clock(),
            bed_time=self.daily.bed_time,
            effective_usage_allowance_minutes=self._effective_usage_allowance_minutes(),
            accumulated_minutes=self.runtime.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            manual_lock_active=self.runtime.manual_lock_active,
            wake_time=self.daily.wake_time,
        )

    def check_and_send_warnings(self):
        """Check if warnings should be sent and send them"""
        # Clear sent-warning memory at wake_time so the 30/15/5/1-minute warnings
        # fire again for the next usage period if the agent runs continuously.
        today = usage_period_date(self.clock(), self.daily.wake_time)
        if today != self.warnings_date:
            self.warnings_sent.clear()
            self.warnings_date = today

        time_remaining = self.get_time_remaining()

        if time_remaining is None or time_remaining <= 0:
            return

        # Fire the smallest applicable threshold first so a kid with only a
        # few minutes left doesn't get a misleading "15 minutes" popup. Once
        # a smaller threshold fires, mark the larger thresholds as also-sent
        # — those longer warning windows never applied to this session and
        # would just be noise if they fired later.
        for warning_mins in sorted(self.warning_intervals):
            warning_key = f"{warning_mins}min"
            if warning_key in self.warnings_sent:
                continue
            if time_remaining > warning_mins:
                continue

            actual_mins = max(1, math.ceil(time_remaining))
            unit = "minute" if actual_mins == 1 else "minutes"
            msg = f"⚠️ Computer will lock in {actual_mins} {unit}!"

            # Only a popup that was shown counts as sent; a failed one is retried.
            self.show_message(msg, "Warning")
            self.warnings_sent.add(warning_key)
            for larger in self.warning_intervals:
                if larger > warning_mins:
                    self.warnings_sent.add(f"{larger}min")
            self.logger.info(
                "Warning sent: %d %s remaining (threshold %d)",
                actual_mins,
                unit,
                warning_mins,
            )
            print(f"[{self.clock():%H:%M:%S}] Warning: {actual_mins} {unit} until lock")
            break

    def currently_in_lock_window(self):
        """
        Return (locked, reason) for whether the agent should currently be
        enforcing a lock. Treats each scheduled lock_time as the start of a
        window that runs until wake_time, so a child who signs in after bedtime
        or before wake is still locked out. Usage-allowance enforcement is a
        simple "minutes-used >= allowance" check for the current wake-to-wake day.
        """
        decision = lock_decision(
            now=self.clock(),
            bed_time=self.daily.bed_time,
            effective_usage_allowance_minutes=self._effective_usage_allowance_minutes(),
            accumulated_minutes=self.runtime.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            manual_lock_active=self.runtime.manual_lock_active,
            wake_time=self.daily.wake_time,
        )
        return decision.should_lock, decision.reason

    def enforcement_lock_state(self) -> tuple[bool, str | None]:
        """Return schedule/limit enforcement without considering manual lock."""
        return enforcement_state(
            now=self.clock(),
            bed_time=self.daily.bed_time,
            effective_usage_allowance_minutes=self._effective_usage_allowance_minutes(),
            accumulated_minutes=self.runtime.accumulated_seconds / 60,
            monitor_user=self.should_monitor_user(),
            wake_time=self.daily.wake_time,
        )

    def get_access_status(self) -> str:
        """Brief access status for the parent panel."""
        enforcement_active, enforcement_reason = self.enforcement_lock_state()
        return format_access_status(
            manual_lock=self.runtime.manual_lock_active,
            enforcement_active=enforcement_active,
            enforcement_reason=enforcement_reason,
            screen_locked=self.check_if_locked(),
        )

    def _enforce_lock_window(self) -> None:
        locked, reason = self.currently_in_lock_window()
        if locked and not self.check_if_locked():
            if reason != self.last_logged_reason:
                self.logger.info(f"Locking PC: {reason}")
                print(f"[{self.clock():%H:%M:%S}] Locking PC: {reason}")
                self.last_logged_reason = reason
            self.lock_pc()
        elif not locked:
            self.last_logged_reason = None

    def _persist_if_due(self) -> None:
        # Persist the accumulator periodically so a crash or power loss
        # doesn't hand the kid a free reset of their daily usage.  A clock that
        # went backwards counts as due, so saving never stalls for hours.
        now = self.clock()
        if self.last_persist_at is not None:
            elapsed = (now - self.last_persist_at).total_seconds()
            if 0 <= elapsed < PERSIST_INTERVAL_SECONDS:
                return
        self.save_state()
        self.last_persist_at = now

    def monitor_step(self) -> None:
        """One iteration of the monitoring loop (everything but the sleep).

        Each phase runs on its own: an error in one (a failing popup, say) is
        logged and must never stop the others, least of all lock enforcement.
        """
        for name, phase in (
            ("tick_accumulator", self.tick_accumulator),
            ("check_and_send_warnings", self.check_and_send_warnings),
            ("enforce_lock_window", self._enforce_lock_window),
            ("persist_state", self._persist_if_due),
        ):
            try:
                phase()
            except Exception as e:
                self._note_failure(name, f"Monitor phase {name} failed: {e}")
            else:
                self._note_recovered(name)

    def run_monitor(self):
        """
        Main monitoring loop. Continuously re-issues LockWorkStation while a
        lock window is active so a child who unlocks the screen with their
        password is immediately re-locked.
        """
        print("PC Time Control is running...")
        while True:
            self.monitor_step()
            time.sleep(1)

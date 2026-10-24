"""Persistent daily settings and runtime state for the Kid PC Monitor agent."""

from __future__ import annotations

import json
import logging
import math
import os
import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any

from kid_pc_monitor.lock_policy import DEFAULT_WAKE_TIME, parse_time_hhmm, usage_period_date

DEFAULT_VALUES_FILE = "daily_settings.json"
STATE_FILE = "state.json"
LEGACY_STATE_FILE = "pc_control_state.json"
LEGACY_INSTALL_CONFIG = "install_config.json"

logger = logging.getLogger(__name__)


@dataclass
class DailySettings:
    bed_time: dtime | None
    wake_time: dtime
    allowance: int | None  # minutes; None = no screen-time cap


@dataclass
class RuntimeState:
    timestamp: datetime
    accumulated_seconds: float
    manual_lock_active: bool
    cumulative_extension_seconds: int


def _format_time(value: dtime) -> str:
    return f"{value.hour:02d}:{value.minute:02d}"


# Values are validated strictly: a wrong type or an out-of-range number is a
# ValueError, never silently coerced (no "false" -> True, no True -> 1 minute,
# no 90.7 -> 90).  Every implementation reading these files must accept exactly
# the same spellings, so the grammar is spelled out here rather than left to
# whatever int()/float()/fromisoformat() happen to accept.
_MAX_ABS_INT = 2**53

_DATE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
_TIME = r"[0-9]{2}(?::[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]+)?)?)?"
_OFFSET = r"(?:Z|[+-][0-9]{2}(?::?[0-9]{2})?)"
_TIMESTAMP_RE = re.compile(rf"{_DATE}(?:[T ]{_TIME}{_OFFSET}?)?")
_DATE_RE = re.compile(_DATE)
_INT_RE = re.compile(r"[+-]?[0-9]+")
_FLOAT_RE = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")


def _parse_timestamp(raw: str) -> datetime:
    """Parse an ISO timestamp as naive wall-clock time (any UTC offset is dropped)."""
    if _TIMESTAMP_RE.fullmatch(raw) is None:
        raise ValueError(f"Invalid timestamp {raw!r}")
    if len(raw) > 10 and int(raw[11:13]) > 23:
        # Newer Pythons accept 24:00 as midnight; the format here does not.
        raise ValueError(f"Invalid timestamp {raw!r}")
    return datetime.fromisoformat(raw).replace(tzinfo=None)


def _parse_date(value: Any, field: str) -> date:
    if not isinstance(value, str) or _DATE_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a YYYY-MM-DD date")
    return date.fromisoformat(value)


def _as_int(value: Any, field: str) -> int:
    """A whole number: an int, an integral float, or a decimal string."""
    number: int
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and math.isfinite(value) and value == math.floor(value):
        number = int(value)
    elif isinstance(value, str) and _INT_RE.fullmatch(value.strip()):
        number = int(value.strip())
    else:
        raise ValueError(f"{field} must be a whole number")
    if abs(number) > _MAX_ABS_INT:
        raise ValueError(f"{field} is out of range")
    return number


def _as_nonneg_int(value: Any, field: str) -> int:
    number = _as_int(value, field)
    if number < 0:
        raise ValueError(f"{field} must not be negative")
    return number


def _as_nonneg_float(value: Any, field: str) -> float:
    """A finite, non-negative number: an int, a float, or a decimal string."""
    number: float
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    if isinstance(value, int):
        if abs(value) > _MAX_ABS_INT:
            raise ValueError(f"{field} is out of range")
        number = float(value)
    elif isinstance(value, float):
        number = value
    elif isinstance(value, str) and _FLOAT_RE.fullmatch(value.strip()):
        number = float(value.strip())
    else:
        raise ValueError(f"{field} must be a number")
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be a finite, non-negative number")
    return number


def _as_bool(value: Any, field: str) -> bool:
    """A JSON boolean; 0/1 and "true"/"false" are tolerated for hand-edited files."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ValueError(f"{field} must be true or false")


def _as_time(value: Any, field: str) -> dtime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an HH:MM string")
    return parse_time_hhmm(value)


def effective_daily_allowance_minutes(daily: DailySettings, runtime: RuntimeState) -> float | None:
    """Return the enforced cap in minutes, or None when there is no usage cap."""
    extension_minutes = runtime.cumulative_extension_seconds / 60
    if daily.allowance is None:
        if extension_minutes <= 0:
            return None
        return extension_minutes
    return daily.allowance + extension_minutes


def runtime_state_is_current(
    runtime: RuntimeState,
    wake_time: dtime,
    now: datetime | None = None,
) -> bool:
    now = now or datetime.now()
    return usage_period_date(runtime.timestamp, wake_time) == usage_period_date(now, wake_time)


def fresh_runtime_state(now: datetime | None = None) -> RuntimeState:
    now = now or datetime.now()
    return RuntimeState(
        timestamp=now,
        accumulated_seconds=0.0,
        manual_lock_active=False,
        cumulative_extension_seconds=0,
    )


def reset_runtime_for_new_period(runtime: RuntimeState, now: datetime | None = None) -> None:
    now = now or datetime.now()
    runtime.timestamp = now
    runtime.accumulated_seconds = 0.0
    runtime.manual_lock_active = False
    runtime.cumulative_extension_seconds = 0


def reset_runtime_if_needed(
    runtime: RuntimeState,
    wake_time: dtime,
    now: datetime | None = None,
) -> bool:
    now = now or datetime.now()
    if runtime_state_is_current(runtime, wake_time, now):
        return False
    reset_runtime_for_new_period(runtime, now)
    return True


def daily_to_dict(daily: DailySettings) -> dict:
    payload: dict = {
        "wake_time": _format_time(daily.wake_time),
        "allowance": daily.allowance,
    }
    if daily.bed_time is not None:
        payload["bed_time"] = _format_time(daily.bed_time)
    else:
        payload["bed_time"] = None
    return payload


def runtime_to_dict(runtime: RuntimeState) -> dict:
    return {
        "timestamp": runtime.timestamp.isoformat(timespec="seconds"),
        "accumulated_seconds": round(runtime.accumulated_seconds, 3),
        "manual_lock_active": runtime.manual_lock_active,
        "cumulative_extension_seconds": runtime.cumulative_extension_seconds,
    }


def load_daily_from_dict(data: dict) -> DailySettings:
    """Build DailySettings from a daily_settings.json payload; ValueError if invalid."""
    wake_time = DEFAULT_WAKE_TIME
    if "wake_time" in data:
        wake_time = _as_time(data["wake_time"], "wake_time")

    bed_time: dtime | None = None
    bed_raw = data.get("bed_time")
    if bed_raw is not None and bed_raw != "":
        bed_time = _as_time(bed_raw, "bed_time")

    allowance: int | None = None
    if data.get("allowance") is not None:
        allowance = _as_nonneg_int(data["allowance"], "allowance")

    return DailySettings(
        bed_time=bed_time,
        wake_time=wake_time,
        allowance=allowance,
    )


def is_complete_daily_dict(data: dict) -> bool:
    """True when wake_time, bed_time, and a positive allowance are all configured."""
    for key in ("wake_time", "bed_time"):
        raw = data.get(key)
        if not isinstance(raw, str) or not raw.strip():
            return False
    if data.get("allowance") is None:
        return False
    try:
        daily = load_daily_from_dict(data)
    except ValueError:
        return False
    return daily.bed_time is not None and daily.allowance is not None and daily.allowance > 0


def find_complete_daily_settings(
    *,
    profile_path: Path | None,
    program_data_path: Path | None,
) -> tuple[DailySettings, Path] | None:
    """Return daily settings and source path when a complete schedule file exists."""
    for path in (profile_path, program_data_path):
        if path is None:
            continue
        data = _read_json(path)
        if data is None or not is_complete_daily_dict(data):
            continue
        try:
            return load_daily_from_dict(data), path
        except ValueError:
            continue
    return None


def load_runtime_from_dict(data: dict) -> RuntimeState:
    """Build RuntimeState from a state.json payload; ValueError if invalid."""
    timestamp_raw = data.get("timestamp")
    if not isinstance(timestamp_raw, str):
        raise ValueError("state.json missing timestamp")
    return RuntimeState(
        timestamp=_parse_timestamp(timestamp_raw),
        accumulated_seconds=(
            _as_nonneg_float(data["accumulated_seconds"], "accumulated_seconds")
            if "accumulated_seconds" in data
            else 0.0
        ),
        manual_lock_active=(
            _as_bool(data["manual_lock_active"], "manual_lock_active")
            if "manual_lock_active" in data
            else False
        ),
        cumulative_extension_seconds=(
            _as_nonneg_int(data["cumulative_extension_seconds"], "cumulative_extension_seconds")
            if "cumulative_extension_seconds" in data
            else 0
        ),
    )


class _PlatformDefault:
    """Sentinel: use the platform's ProgramData directory (Windows only)."""


PLATFORM_DEFAULT = _PlatformDefault()
ProgramDataDir = Path | None | _PlatformDefault


def _program_data_dir(program_data_dir: ProgramDataDir = PLATFORM_DEFAULT) -> Path | None:
    """The KidPCMonitor ProgramData directory, or None when there isn't one.

    An explicit ``Path`` (or ``None``) overrides the platform lookup so tests
    and the Go port can pin it.
    """
    if not isinstance(program_data_dir, _PlatformDefault):
        return program_data_dir
    if sys.platform != "win32":
        return None
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(program_data) / "KidPCMonitor"


def program_data_daily_path(program_data_dir: ProgramDataDir = PLATFORM_DEFAULT) -> Path | None:
    base = _program_data_dir(program_data_dir)
    return None if base is None else base / DEFAULT_VALUES_FILE


def program_data_legacy_install_config_path(
    program_data_dir: ProgramDataDir = PLATFORM_DEFAULT,
) -> Path | None:
    base = _program_data_dir(program_data_dir)
    return None if base is None else base / LEGACY_INSTALL_CONFIG


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _load_json_file(path: Path) -> tuple[dict | None, str | None]:
    """Read a JSON object from ``path``.

    Returns ``(data, None)``, ``(None, None)`` when the file does not exist, or
    ``(None, reason)`` when it exists but is not usable (not UTF-8, not JSON,
    NaN/Infinity, or not an object).  A leading UTF-8 byte-order mark, which
    Notepad adds, is accepted.  OSError (a file we could not read at all, for
    example because another program has it open) is *not* a verdict on the
    file and propagates.
    """
    if not path.is_file():
        return None, None
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        return None, f"not valid UTF-8: {exc}"
    try:
        data = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        return None, f"not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "not a JSON object"
    return data, None


def _read_json(path: Path) -> dict | None:
    """Best-effort read of a file we do not own (installer output): problems are ignored."""
    try:
        data, reason = _load_json_file(path)
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return None
    if reason is not None:
        logger.warning("Ignoring %s: %s", path, reason)
    return data


def program_data_target_user(program_data_dir: ProgramDataDir = PLATFORM_DEFAULT) -> str | None:
    """Return the monitored account from ProgramData daily_settings.json, if set."""
    path = program_data_daily_path(program_data_dir)
    if path is None:
        return None
    data = _read_json(path)
    if data is None:
        return None
    target = data.get("target_user")
    if isinstance(target, str) and target.strip():
        return target.strip()
    return None


def _backup_path(path: Path) -> Path:
    return path.with_name(path.name + ".bak")


def _write_json(
    path: Path, payload: dict, *, validate: Callable[[dict], object] | None = None
) -> None:
    """Atomically replace ``path``, first keeping the current valid file as ``<name>.bak``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if validate is not None:
        current, reason = _load_json_file(path)
        if current is not None and reason is None:
            try:
                validate(current)
            except ValueError:
                pass
            else:
                shutil.copy2(path, _backup_path(path))
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _legacy_lock_times_to_bed_time(lock_times_raw: Any) -> dtime | None:
    """The first legacy lock time becomes the bed time."""
    if lock_times_raw is None:
        return None
    if not isinstance(lock_times_raw, list):
        raise ValueError("lock_times must be a list")
    if not lock_times_raw:
        return None
    first = lock_times_raw[0]
    if isinstance(first, str) and ":" in first:
        return parse_time_hhmm(first)
    return None


def migrate_legacy_state(
    legacy_path: Path,
    *,
    current_user: str,
    now: datetime | None = None,
) -> tuple[DailySettings, RuntimeState] | None:
    legacy = _read_json(legacy_path)
    if legacy is None:
        return None
    migrated = legacy_to_state(legacy, now=now)
    logger.info(
        "Migrated legacy state for %s from %s",
        current_user,
        legacy_path,
    )
    return migrated


def legacy_to_state(
    legacy: dict, *, now: datetime | None = None
) -> tuple[DailySettings, RuntimeState]:
    """Convert a legacy ``pc_control_state.json`` payload to current settings and state.

    Raises ValueError if the payload is not usable.
    """
    now = now or datetime.now()

    wake_time = DEFAULT_WAKE_TIME
    if isinstance(legacy.get("wake_time"), str):
        wake_time = parse_time_hhmm(legacy["wake_time"])

    bed_time = _legacy_lock_times_to_bed_time(legacy.get("lock_times"))
    allowance: int | None = None
    if legacy.get("usage_allowance") is not None:
        allowance = _as_nonneg_int(legacy["usage_allowance"], "usage_allowance")

    daily = DailySettings(
        bed_time=bed_time,
        wake_time=wake_time,
        allowance=allowance,
    )

    runtime = RuntimeState(
        timestamp=now,
        accumulated_seconds=(
            _as_nonneg_float(legacy["accumulated_seconds"], "accumulated_seconds")
            if "accumulated_seconds" in legacy
            else 0.0
        ),
        manual_lock_active=(
            _as_bool(legacy["manual_lock_active"], "manual_lock_active")
            if "manual_lock_active" in legacy
            else False
        ),
        cumulative_extension_seconds=0,
    )

    # Usage recorded for an earlier period does not carry over.
    if "accumulated_date" in legacy:
        saved_date = _parse_date(legacy["accumulated_date"], "accumulated_date")
        if saved_date < usage_period_date(now, wake_time):
            reset_runtime_for_new_period(runtime, now)

    return daily, runtime


def _daily_path_for(program_data_dir: ProgramDataDir) -> Path | None:
    # No argument on the default path keeps ``program_data_daily_path`` patchable.
    if isinstance(program_data_dir, _PlatformDefault):
        return program_data_daily_path()
    return program_data_daily_path(program_data_dir)


def _legacy_install_path_for(program_data_dir: ProgramDataDir) -> Path | None:
    if isinstance(program_data_dir, _PlatformDefault):
        return program_data_legacy_install_config_path()
    return program_data_legacy_install_config_path(program_data_dir)


def _bootstrap_daily_from_program_data(
    current_user: str, program_data_dir: ProgramDataDir = PLATFORM_DEFAULT
) -> DailySettings | None:
    for path in (_daily_path_for(program_data_dir),):
        if path is None:
            continue
        data = _read_json(path)
        if data is None:
            continue
        target_user = data.get("target_user")
        if isinstance(target_user, str) and target_user:
            if target_user.lower() != current_user.lower():
                continue
        try:
            return load_daily_from_dict(data)
        except ValueError as exc:
            logger.warning("Invalid program-data daily settings at %s: %s", path, exc)

    legacy_install = _legacy_install_path_for(program_data_dir)
    if legacy_install is not None:
        data = _read_json(legacy_install)
        if data is not None:
            target_user = data.get("target_user")
            if isinstance(target_user, str) and target_user:
                if target_user.lower() != current_user.lower():
                    return None
            wake_raw = data.get("wake_time")
            if isinstance(wake_raw, str):
                try:
                    wake_time = parse_time_hhmm(wake_raw)
                    return DailySettings(
                        bed_time=None,
                        wake_time=wake_time,
                        allowance=None,
                    )
                except ValueError:
                    pass
    return None


@dataclass(frozen=True)
class StateProblem:
    """Something wrong with a state file that load() worked around."""

    file: str
    action: str  # "quarantined", "restored_from_backup" or "ignored"
    reason: str


class AgentStateStore:
    """Read/write daily_settings.json and state.json under the agent data directory.

    Files are never silently discarded.  A file that exists but is unusable is
    renamed to ``<name>.corrupt-<timestamp>``; the last good copy
    (``<name>.bak``, refreshed on every save) is restored in its place, and only
    if there is none do defaults apply.  A file that has simply gone missing is
    restored from its backup too.  Every such event is listed in ``problems``
    after ``load()``.
    """

    def __init__(
        self,
        data_directory: Path,
        *,
        current_user: str,
        clock: Callable[[], datetime] = datetime.now,
        program_data_dir: ProgramDataDir = PLATFORM_DEFAULT,
    ) -> None:
        self.data_directory = data_directory
        self.current_user = current_user
        self.clock = clock
        self.program_data_dir = program_data_dir
        self.daily_path = data_directory / DEFAULT_VALUES_FILE
        self.state_path = data_directory / STATE_FILE
        self.legacy_state_path = data_directory / LEGACY_STATE_FILE
        self.problems: list[StateProblem] = []

    def load(self) -> tuple[DailySettings, RuntimeState]:
        """Load settings and runtime state, creating or recovering files as needed.

        Only OSError (a file that could not be read or written) escapes.
        """
        self.problems = []
        daily = self._read_validated(self.daily_path, load_daily_from_dict)
        runtime = self._read_validated(self.state_path, load_runtime_from_dict)
        runtime_on_disk = runtime is not None

        daily_derived = daily is None
        if daily is None:
            daily, legacy_runtime = self._derive_daily()
            if runtime is None:
                runtime = legacy_runtime
        if runtime is None:
            runtime = fresh_runtime_state(self.clock())

        if daily_derived:
            # A fresh install, an upgrade from the legacy file, or settings that
            # could not be recovered: persist what we settled on.
            self._write_daily(daily)
            if not runtime_on_disk:
                runtime.timestamp = self.clock()
                self._write_runtime(runtime)

        if reset_runtime_if_needed(runtime, daily.wake_time, self.clock()):
            logger.info("Runtime state is from a previous usage period; resetting daily counters")
        return daily, runtime

    def save(self, daily: DailySettings, runtime: RuntimeState) -> None:
        runtime.timestamp = self.clock()
        self._write_daily(daily)
        self._write_runtime(runtime)

    def _write_daily(self, daily: DailySettings) -> None:
        _write_json(self.daily_path, daily_to_dict(daily), validate=load_daily_from_dict)

    def _write_runtime(self, runtime: RuntimeState) -> None:
        _write_json(self.state_path, runtime_to_dict(runtime), validate=load_runtime_from_dict)

    def _problem(self, file: str, action: str, reason: str) -> None:
        logger.warning("%s: %s (%s)", file, action.replace("_", " "), reason)
        self.problems.append(StateProblem(file, action, reason))

    def _quarantine(self, path: Path, reason: str) -> None:
        stamp = f"{self.clock():%Y%m%dT%H%M%S}"
        target = path.with_name(f"{path.name}.corrupt-{stamp}")
        try:
            os.replace(path, target)
        except OSError as exc:
            logger.error("Could not move aside %s: %s", path, exc)
        self._problem(path.name, "quarantined", reason)

    def _read_validated(self, path: Path, loader: Callable[[dict], Any]) -> Any:
        """Return ``loader(file)`` for ``path``, else for its backup, else None."""
        for candidate in (path, _backup_path(path)):
            data, reason = _load_json_file(candidate)
            if data is not None:
                try:
                    value = loader(data)
                except ValueError as exc:
                    reason = str(exc)
                else:
                    if candidate != path:
                        self._restore(candidate, path)
                    return value
            if reason is not None:
                self._quarantine(candidate, reason)
        return None

    def _restore(self, backup: Path, path: Path) -> None:
        try:
            shutil.copy2(backup, path)
        except OSError as exc:
            logger.error("Could not restore %s from %s: %s", path, backup, exc)
        self._problem(path.name, "restored_from_backup", f"from {backup.name}")

    def _derive_daily(self) -> tuple[DailySettings, RuntimeState | None]:
        """Settings (and maybe runtime) for an install with no usable daily_settings.json."""
        try:
            migrated = migrate_legacy_state(
                self.legacy_state_path, current_user=self.current_user, now=self.clock()
            )
        except ValueError as exc:
            self._problem(self.legacy_state_path.name, "ignored", str(exc))
            migrated = None
        if migrated is not None:
            return migrated

        bootstrapped = _bootstrap_daily_from_program_data(self.current_user, self.program_data_dir)
        if bootstrapped is not None:
            return bootstrapped, None

        return DailySettings(bed_time=None, wake_time=DEFAULT_WAKE_TIME, allowance=None), None

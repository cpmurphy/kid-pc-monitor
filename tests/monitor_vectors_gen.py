"""Generate the golden monitoring-loop vectors shared by the Python and Go implementations.

A snapshot of :class:`kid_pc_monitor.pc_time_control.PCTimeControl` driven through
scripted scenarios, written to ``testdata/monitor/vectors.json``.  ``go/monitor``
replays every scenario with a fake clock and platform and must produce the same
platform calls, log lines, state files and in-memory state after every step.
``tests/test_monitor_vectors.py`` fails when the file is stale.

    python tests/monitor_vectors_gen.py          # rewrite the vectors file
    python tests/monitor_vectors_gen.py --check  # exit 1 if the file is stale

A scenario is a ``setup`` (clock, user lists, state files, platform) and a list of
``steps``.  Each step records what its op did: platform ``events``, ``logs`` from the
``PCTimeControl`` logger, state ``files`` that changed, the op's ``result`` and a
``view`` of the control's in-memory state
(the fields that changed; the full view is in ``init``).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import random
import sys
import tempfile
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kid_pc_monitor.host_platform import HostPlatform  # noqa: E402
from kid_pc_monitor.pc_time_control import PCTimeControl  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "monitor" / "vectors.json"

# Log lines whose tail is OS- or path-specific (error text, state-file reasons):
# only the part before the first " (" or ": " after these prefixes is compared.
LOG_PREFIX_ONLY = [
    "State file problem:",
    "Error loading state:",
    "Error saving state:",
    "Platform check_session_locked failed:",
    "Platform session_is_active failed:",
]

STATE_FILES = ("daily_settings.json", "state.json")

# The state store logs through this tree; keep its warnings off stderr.
logging.getLogger("kid_pc_monitor").addHandler(logging.NullHandler())
START = "2026-05-17T12:00:00"


def normalize_log(message: str) -> str:
    for prefix in LOG_PREFIX_ONLY:
        if message.startswith(prefix):
            return prefix
    return message


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class Boom(RuntimeError):
    pass


class RecordingPlatform(HostPlatform):
    def __init__(self, spec: dict[str, Any]) -> None:
        self.locked = bool(spec.get("locked", False))
        self.active = bool(spec.get("active", True))
        self.lock_sets_locked = bool(spec.get("lock_sets_locked", True))
        self.fail: set[str] = set(spec.get("fail", []))
        self.events: list[list[Any]] = []

    def configure(self, spec: dict[str, Any]) -> None:
        if "locked" in spec:
            self.locked = bool(spec["locked"])
        if "active" in spec:
            self.active = bool(spec["active"])
        if "lock_sets_locked" in spec:
            self.lock_sets_locked = bool(spec["lock_sets_locked"])
        if "fail" in spec:
            self.fail = set(spec["fail"])

    def _check(self, name: str) -> None:
        if name in self.fail:
            raise Boom("boom")

    def check_session_locked(self) -> bool:
        self._check("check_session_locked")
        return self.locked

    def session_is_active(self) -> bool:
        self._check("session_is_active")
        return self.active and not self.locked

    def lock_workstation(self) -> None:
        self.events.append(["lock"])
        self._check("lock_workstation")
        if self.lock_sets_locked:
            self.locked = True

    def shutdown(self, seconds: int = 60) -> None:
        self.events.append(["shutdown", seconds])
        self._check("shutdown")

    def cancel_shutdown(self) -> None:
        self.events.append(["cancel_shutdown"])
        self._check("cancel_shutdown")

    def show_message(self, message: str, title: str = "PC Time Control") -> None:
        self.events.append(["message", title, message])
        self._check("show_message")

    def get_hostname(self) -> str:
        return "test-pc"


class LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[list[str]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append([record.levelname, normalize_log(record.getMessage())])


class Clock:
    def __init__(self, at: str) -> None:
        self.now = datetime.fromisoformat(at)

    def __call__(self) -> datetime:
        return self.now


# ---------------------------------------------------------------------------
# Running a scenario
# ---------------------------------------------------------------------------
def iso(value: date | None) -> str | None:
    return None if value is None else value.isoformat()


def hhmm(value: Any) -> str | None:
    return None if value is None else f"{value.hour:02d}:{value.minute:02d}"


def view(control: PCTimeControl) -> dict[str, Any]:
    """In-memory state; reads nothing from the platform, so it cannot disturb a step."""
    locked, reason = control.currently_in_lock_window()
    enforcement_active, enforcement_reason = control.enforcement_lock_state()
    return {
        "bed_time": hhmm(control.daily.bed_time),
        "wake_time": hhmm(control.daily.wake_time),
        "allowance": control.daily.allowance,
        "timestamp": iso(control.runtime.timestamp),
        "accumulated_seconds": control.runtime.accumulated_seconds,
        "manual_lock_active": control.runtime.manual_lock_active,
        "extension_seconds": control.runtime.cumulative_extension_seconds,
        "warnings_sent": sorted(control.warnings_sent),
        "warnings_date": iso(control.warnings_date),
        "last_tick_at": iso(control.last_tick_at),
        "last_persist_at": iso(control.last_persist_at),
        "is_locked": control.is_locked,
        "last_logged_reason": control.last_logged_reason,
        "state_load_failed": control.state_load_failed,
        "step_errors": sorted(control.step_errors),
        "time_remaining": control.get_time_remaining(),
        "lock_window": [locked, reason],
        "enforcement": [enforcement_active, enforcement_reason],
    }


def read_files(directory: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in STATE_FILES:
        path = directory / name
        if not path.is_file():
            out[name] = None
            continue
        text = path.read_text(encoding="utf-8")
        try:
            out[name] = json.loads(text)
        except ValueError:
            out[name] = {"__text__": text}
    return out


def apply_file_ops(directory: Path, files: dict[str, Any]) -> None:
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")


CALLS = {
    "set_bed_time": lambda c, a: c.set_bed_time(*a),
    "clear_bed_time": lambda c, a: c.clear_bed_time(),
    "set_wake_time": lambda c, a: c.set_wake_time(*a),
    "set_daily_allowance": lambda c, a: c.set_daily_allowance(*a),
    "extend_time": lambda c, a: c.extend_time(*a),
    "clear_extensions": lambda c, a: c.clear_extensions(),
    "clear_warnings": lambda c, a: c.warnings_sent.clear(),
    "engage_manual_lock": lambda c, a: c.engage_manual_lock(),
    "clear_manual_lock": lambda c, a: c.clear_manual_lock(),
    "send_parent_message": lambda c, a: c.send_parent_message(*a),
    "shutdown_pc": lambda c, a: c.shutdown_pc(*a),
    "cancel_shutdown": lambda c, a: c.cancel_shutdown(),
    "save_state": lambda c, a: c.save_state(),
    "load_state": lambda c, a: c.load_state(),
    "lock_pc": lambda c, a: c.lock_pc(),
}

READS = {
    "time_remaining": lambda c: c.get_time_remaining(),
    "access_status": lambda c: c.get_access_status(),
    "enforcement_lock_state": lambda c: list(c.enforcement_lock_state()),
    "lock_window": lambda c: list(c.currently_in_lock_window()),
    "check_if_locked": lambda c: c.check_if_locked(),
    "session_is_active": lambda c: c.session_is_active(),
}

LOOPS = {
    "tick": lambda c: c.tick_accumulator(),
    "warnings": lambda c: c.check_and_send_warnings(),
    "step": lambda c: c.monitor_step(),
    "observe": lambda c: c.observe_lock_state(),
}


def run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    setup = scenario["setup"]
    clock = Clock(setup["now"])
    platform = RecordingPlatform(setup.get("platform", {}))
    capture = LogCapture()
    logger = logging.getLogger("PCTimeControl")
    old_level, old_propagate = logger.level, logger.propagate
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(capture)
    try:
        with (
            tempfile.TemporaryDirectory() as tmp,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            directory = Path(tmp)
            apply_file_ops(directory, setup.get("files", {}))
            control = PCTimeControl(
                platform=platform,
                monitored_users=setup.get("monitored", []),
                exempt_users=setup.get("exempt", []),
                data_directory=directory,
                start_background_threads=False,
                clock=clock,
                current_user=setup.get("user", "kid"),
                program_data_dir=None,
            )
            files_seen = read_files(directory)
            view_seen = view(control)
            record: dict[str, Any] = {
                "init": {
                    "logs": capture.records,
                    "events": platform.events,
                    "view": view_seen,
                    "files": files_seen,
                },
                "steps": [],
            }
            capture.records = []
            platform.events = []
            for op in scenario["steps"]:
                result: Any = None
                try:
                    result = run_op(op, control, platform, clock, directory)
                except Exception as exc:  # recorded, not fatal: some ops are meant to fail
                    result = {"raised": type(exc).__name__}
                files_now = read_files(directory)
                changed = {k: v for k, v in files_now.items() if v != files_seen.get(k)}
                files_seen = files_now
                view_now = view(control)
                step = {
                    "events": platform.events,
                    "logs": capture.records,
                    "files": changed,
                    # Only the fields that changed since the previous step.
                    "view": {k: v for k, v in view_now.items() if v != view_seen[k]},
                }
                view_seen = view_now
                if result is not None:
                    step["result"] = result
                record["steps"].append(step)
                capture.records = []
                platform.events = []
    finally:
        logger.removeHandler(capture)
        logger.setLevel(old_level)
        logger.propagate = old_propagate
    return {"name": scenario["name"], "setup": setup, "ops": scenario["steps"], **record}


def run_op(
    op: dict[str, Any],
    control: PCTimeControl,
    platform: RecordingPlatform,
    clock: Clock,
    directory: Path,
) -> Any:
    kind = op["op"]
    if kind == "advance":
        clock.now += timedelta(microseconds=op["us"])
    elif kind == "set_clock":
        clock.now = datetime.fromisoformat(op["at"])
    elif kind == "platform":
        platform.configure(op)
    elif kind in LOOPS:
        LOOPS[kind](control)
    elif kind == "call":
        CALLS[op["method"]](control, op.get("args", []))
    elif kind == "read":
        return READS[op["what"]](control)
    elif kind == "write_file":
        (directory / op["name"]).write_text(op["text"], encoding="utf-8")
    elif kind == "delete_file":
        (directory / op["name"]).unlink(missing_ok=True)
    elif kind == "set_accumulated":
        control.runtime.accumulated_seconds = op["seconds"]
    elif kind == "mkdir":
        (directory / op["name"]).mkdir()
    elif kind == "rmdir":
        (directory / op["name"]).rmdir()
    elif kind == "write_log":
        control.agent_log_path.write_bytes(bytes.fromhex(op["hex"]))
    elif kind == "read_tail":
        lines, truncated = control.read_log_tail(tail=op["tail"])
        return {"lines": lines, "truncated": truncated}
    else:
        raise AssertionError(f"unknown op {kind}")
    return None


# ---------------------------------------------------------------------------
# Scenario building blocks
# ---------------------------------------------------------------------------
def daily_text(**fields: Any) -> str:
    return json.dumps(fields)


def state_text(
    timestamp: str = START,
    accumulated: float = 0,
    manual: bool = False,
    extension: int = 0,
) -> str:
    return json.dumps(
        {
            "timestamp": timestamp,
            "accumulated_seconds": accumulated,
            "manual_lock_active": manual,
            "cumulative_extension_seconds": extension,
        }
    )


def setup(
    now: str = START,
    *,
    daily: dict[str, Any] | None = None,
    state: dict[str, Any] | None = None,
    files: dict[str, str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {"now": now, "files": dict(files or {})}
    out["files"].setdefault(
        "daily_settings.json",
        daily_text(**(daily if daily is not None else {"wake_time": "07:00"})),
    )
    out["files"].setdefault("state.json", state_text(**{"timestamp": now, **(state or {})}))
    out.update(extra)
    return out


def adv(seconds: float) -> dict[str, Any]:
    return {"op": "advance", "us": round(seconds * 1_000_000)}


def call(method: str, *args: Any) -> dict[str, Any]:
    return {"op": "call", "method": method, "args": list(args)}


def acc(minutes: float) -> dict[str, Any]:
    """Set the accumulated usage directly (ticks only credit gaps under a minute)."""
    return {"op": "set_accumulated", "seconds": minutes * 60}


def read(what: str) -> dict[str, Any]:
    return {"op": "read", "what": what}


STEP = {"op": "step"}
TICK = {"op": "tick"}
WARN = {"op": "warnings"}


def plat(**spec: Any) -> dict[str, Any]:
    return {"op": "platform", **spec}


def seconds(n: int, *, each: float = 1.0, op: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for _ in range(n):
        steps += [adv(each), op or STEP]
    return steps


def fixed_scenarios() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(name: str, setup_: dict[str, Any], steps: list[dict[str, Any]]) -> None:
        out.append({"name": name, "setup": setup_, "steps": steps})

    # --- usage accounting -------------------------------------------------
    add(
        "accrual_basic",
        setup(daily={"wake_time": "07:00", "allowance": 120}),
        [TICK] + seconds(5, op=TICK) + [read("time_remaining")],
    )
    add(
        "accrual_gap_clamps",
        setup(daily={"wake_time": "07:00", "allowance": 120}),
        [
            TICK,
            adv(59.999999),
            TICK,  # credited
            adv(60),
            TICK,  # exactly 60: not credited
            adv(0.5),
            TICK,  # credited
            adv(-3),
            TICK,  # clock went backwards: not credited
            adv(0),
            TICK,  # no time passed: not credited
            adv(61),
            TICK,
            adv(0.000001),
            TICK,
        ],
    )
    add(
        "accrual_paused_while_inactive",
        setup(daily={"wake_time": "07:00", "allowance": 120}),
        [TICK, adv(1), TICK, plat(active=False), adv(1), TICK, adv(1), TICK]
        + [plat(active=True), adv(1), TICK, adv(1), TICK]
        + [plat(locked=True), adv(1), TICK, plat(locked=False), adv(1), TICK, adv(1), TICK],
    )
    add(
        "accrual_not_counted_for_exempt_user",
        setup(daily={"wake_time": "07:00", "allowance": 120}, exempt=["kid"]),
        [TICK] + seconds(3, op=TICK) + [read("time_remaining"), read("access_status")],
    )
    add(
        "accrual_not_counted_in_curfew",
        setup(
            "2026-05-17T21:00:00",
            daily={"wake_time": "07:00", "bed_time": "21:00", "allowance": 60},
        ),
        [TICK] + seconds(3, op=TICK),
    )
    add(
        "accrual_not_counted_with_manual_lock",
        setup(daily={"wake_time": "07:00", "allowance": 60}, state={"manual": True}),
        [TICK] + seconds(3, op=TICK),
    )

    # --- wake-time rollover ----------------------------------------------
    add(
        "rollover_at_wake_time",
        setup(
            "2026-05-17T06:59:58",
            daily={"wake_time": "07:00", "allowance": 60},
            state={"accumulated": 3000, "extension": 600, "manual": True},
        ),
        [STEP, adv(1), STEP, adv(1), STEP, adv(1), STEP, read("time_remaining")],
    )
    add(
        "stale_state_resets_on_load",
        setup(
            "2026-05-18T09:00:00",
            daily={"wake_time": "07:00", "allowance": 60},
            files={"state.json": state_text("2026-05-17T08:00:00", 1800, True, 900)},
        ),
        [STEP],
    )
    add(
        "rollover_with_midnight_wake_time",
        setup(
            "2026-05-17T23:59:58",
            daily={"wake_time": "00:00", "allowance": 60},
            state={"accumulated": 1000},
        ),
        [STEP, adv(1), STEP, adv(1), STEP, adv(1), STEP],
    )

    # --- warnings ---------------------------------------------------------
    warn_setup = setup(daily={"wake_time": "07:00", "allowance": 40})
    add(
        "warnings_walk_down",
        warn_setup,
        [WARN]
        + [acc(5), WARN]  # 35 left
        + [acc(11), WARN]  # 29 left: 30 fires
        + [acc(24), WARN]  # 16 left
        + [acc(25), WARN]  # 15 left: fires
        + [acc(34.9), WARN]  # just over 5 left
        + [acc(35), WARN]  # 5 left: fires
        + [acc(36), WARN, acc(38.5), WARN]  # ~1.5 left: 1 fires
        + [acc(39.99), WARN, acc(40), WARN, STEP],
    )
    for name, accumulated in (
        ("warnings_skip_to_five", 35 * 60 + 10),
        ("warnings_skip_to_one", 39 * 60 + 1),
        ("warnings_exact_threshold", 10 * 60),
        ("warnings_fractional_rounds_up", 39 * 60 + 59.5),
        ("warnings_none_when_far", 5 * 60),
        ("warnings_none_when_locked_already", 41 * 60),
    ):
        add(
            name,
            setup(
                daily={"wake_time": "07:00", "allowance": 40}, state={"accumulated": accumulated}
            ),
            [WARN, WARN, adv(1), STEP, STEP],
        )
    add(
        "warnings_extend_clears_and_refires",
        setup(daily={"wake_time": "07:00", "allowance": 40}, state={"accumulated": 38 * 60}),
        [
            WARN,
            WARN,
            call("extend_time", 10),
            WARN,
            call("extend_time", 5),
            WARN,
            read("time_remaining"),
        ],
    )
    add(
        "warnings_bedtime_countdown",
        setup("2026-05-17T20:25:00", daily={"wake_time": "07:00", "bed_time": "21:00"}),
        [
            WARN,
            adv(60 * 5),
            WARN,
            adv(60 * 10),
            WARN,
            adv(60 * 14),
            WARN,
            adv(30),
            WARN,
            adv(30),
            WARN,
        ],
    )
    add(
        "warnings_popup_failure_retries",
        setup(daily={"wake_time": "07:00", "allowance": 40}, state={"accumulated": 38 * 60}),
        [plat(fail=["show_message"]), STEP, STEP, plat(fail=[]), STEP, STEP],
    )
    add(
        "warnings_cleared_at_period_change",
        setup(
            "2026-05-17T06:58:00",
            daily={"wake_time": "07:00", "allowance": 5},
            state={"accumulated": 4 * 60 + 30, "timestamp": "2026-05-16T12:00:00"},
        ),
        [WARN, adv(120), STEP, WARN, adv(1), STEP],
    )
    add(
        "warnings_exempt_user_never_warned",
        setup(
            daily={"wake_time": "07:00", "allowance": 40},
            state={"accumulated": 39 * 60},
            exempt=["kid"],
        ),
        [WARN, STEP],
    )

    # --- lock enforcement -------------------------------------------------
    curfew = setup("2026-05-17T20:59:58", daily={"wake_time": "07:00", "bed_time": "21:00"})
    add(
        "enforce_bedtime_relocks_after_unlock",
        curfew,
        [STEP, adv(1), STEP, adv(1), STEP]  # 21:00:00 -> lock once
        + [plat(locked=False), adv(1), STEP]  # child unlocks: locked again
        + [plat(locked=False), adv(1), STEP, plat(locked=False), adv(1), STEP],
    )
    add(
        "enforce_reason_logged_once_per_change",
        setup(
            "2026-05-17T20:59:59", daily={"wake_time": "07:00", "bed_time": "21:00", "allowance": 1}
        ),
        [STEP, adv(2), STEP, plat(locked=False), adv(1), STEP, call("set_wake_time", 21, 30), STEP]
        + [
            plat(locked=False),
            adv(1),
            STEP,
            call("clear_bed_time"),
            plat(locked=False),
            STEP,
            STEP,
        ],
    )
    add(
        "enforce_manual_lock_roundtrip",
        setup(daily={"wake_time": "07:00"}),
        [
            STEP,
            call("engage_manual_lock"),
            plat(locked=False),
            STEP,
            call("clear_manual_lock"),
            STEP,
        ]
        + [plat(locked=False), STEP, call("engage_manual_lock"), STEP, read("access_status")],
    )
    add(
        "enforce_lock_failure_keeps_trying",
        setup(daily={"wake_time": "07:00"}, state={"manual": True}),
        [plat(fail=["lock_workstation"], lock_sets_locked=False), STEP, STEP, STEP]
        + [plat(fail=[]), STEP, STEP],
    )
    add(
        "enforce_exempt_user_never_locked",
        setup(
            daily={"wake_time": "07:00", "bed_time": "12:00"},
            state={"manual": True},
            exempt=["kid"],
        ),
        [STEP, STEP, read("access_status"), read("lock_window")],
    )
    add(
        "enforce_monitored_list_only",
        setup(daily={"wake_time": "07:00", "bed_time": "12:00"}, monitored=["someone"]),
        [STEP, read("lock_window")],
    )
    add(
        "enforce_allowance_reached_locks",
        setup(daily={"wake_time": "07:00", "allowance": 1}, state={"accumulated": 59.5}),
        [
            STEP,
            adv(0.4),
            STEP,
            adv(0.4),
            STEP,
            adv(0.4),
            STEP,
            read("access_status"),
            call("extend_time", 1),
        ]
        + [plat(locked=False), STEP, read("access_status")],
    )
    add(
        "enforce_before_wake_time",
        setup("2026-05-17T03:00:00", daily={"wake_time": "07:00", "bed_time": "21:00"}),
        [STEP, read("access_status"), read("time_remaining")],
    )

    # --- platform failures ------------------------------------------------
    add(
        "platform_query_failures",
        setup(daily={"wake_time": "07:00", "allowance": 60}, state={"manual": True}),
        [
            plat(fail=["check_session_locked"]),
            STEP,
            STEP,
            read("check_if_locked"),
            plat(fail=[]),
            STEP,
        ]
        + [plat(fail=["session_is_active"], locked=False), call("clear_manual_lock"), adv(1), STEP]
        + [adv(1), STEP, read("session_is_active"), plat(fail=[]), adv(1), STEP],
    )
    add(
        "platform_all_failing",
        setup("2026-05-17T22:00:00", daily={"wake_time": "07:00", "bed_time": "21:00"}),
        [
            plat(
                fail=[
                    "check_session_locked",
                    "session_is_active",
                    "lock_workstation",
                    "show_message",
                ]
            )
        ]
        + [STEP, STEP, adv(1), STEP, plat(fail=[]), STEP],
    )

    # --- persistence ------------------------------------------------------
    add(
        "persist_throttle",
        setup(daily={"wake_time": "07:00", "allowance": 120}),
        [STEP, adv(1), STEP, adv(29), STEP, adv(29.999999), STEP, adv(0.000001), STEP, adv(1), STEP]
        + [adv(59), STEP, adv(60), STEP, adv(-7200), STEP, adv(30), STEP, adv(60), STEP],
    )
    add(
        "persist_writes_rounded_accumulator",
        setup(daily={"wake_time": "07:00", "allowance": 120}, state={"accumulated": 10.12345}),
        [STEP, adv(0.5), TICK, adv(0.3333), TICK, call("save_state")],
    )

    # --- parent actions ---------------------------------------------------
    add(
        "actions_schedule_and_limits",
        setup(daily={"wake_time": "07:00"}),
        [
            call("set_bed_time", 21, 30),
            call("set_daily_allowance", 90),
            call("save_state"),
            read("time_remaining"),
            call("set_daily_allowance", None),
            call("clear_bed_time"),
            call("save_state"),
            read("time_remaining"),
            call("set_bed_time", 0, 0),
            call("set_bed_time", 23, 59),
            call("set_daily_allowance", 0),
            call("save_state"),
        ],
    )
    add(
        "actions_extend_and_clear",
        setup(
            daily={"wake_time": "07:00", "allowance": 60},
            state={"accumulated": 3500, "manual": True},
        ),
        [
            call("extend_time", 15),
            read("time_remaining"),
            call("extend_time", 1),
            call("extend_time", 1440),
            call("clear_extensions"),
            call("save_state"),
        ],
    )
    add(
        "actions_extend_without_allowance",
        setup(daily={"wake_time": "07:00"}),
        [
            read("time_remaining"),
            call("extend_time", 30),
            read("time_remaining"),
            call("clear_extensions"),
        ]
        + [read("time_remaining")],
    )
    for name, now, old_wake, new_wake in (
        ("wake_time_moves_forward_past_now_resets", "2026-05-17T07:09:00", "09:00", "07:00"),
        ("wake_time_moves_later_no_reset", "2026-05-17T06:30:00", "06:00", "07:00"),
        ("wake_time_same_period_no_reset", "2026-05-17T12:00:00", "07:00", "08:30"),
        ("wake_time_to_midnight", "2026-05-17T12:00:00", "07:00", "00:00"),
        ("wake_time_from_midnight", "2026-05-17T00:30:00", "00:00", "07:00"),
    ):
        h, m = new_wake.split(":")
        add(
            name,
            setup(
                now,
                daily={"wake_time": old_wake, "allowance": 60},
                state={"accumulated": 1200, "extension": 300, "manual": True},
            ),
            [
                call("clear_manual_lock"),
                plat(locked=False),
                STEP,
                adv(1),
                STEP,  # a tick is in flight when the wake time changes
                WARN,
                call("set_wake_time", int(h), int(m)),
                read("time_remaining"),
                call("save_state"),
                adv(1),
                STEP,
            ],
        )
    long_text = "x" * 119 + "é" + "tail"
    for name, text in (
        ("message_short", "Dinner time"),
        ("message_exactly_120", "m" * 120),
        ("message_121_truncated", "m" * 121),
        ("message_astral_truncation", "😀" * 119 + "ab" + "😀"),
        ("message_multiline", "line1\nline2\r\n\ttab"),
        ("message_long_unicode", long_text),
    ):
        add(
            name,
            setup(),
            [call("send_parent_message", text)],
        )
    add(
        "message_failure", setup(), [plat(fail=["show_message"]), call("send_parent_message", "hi")]
    )
    add(
        "shutdown_and_cancel",
        setup(),
        [
            call("shutdown_pc"),
            call("shutdown_pc", 0),
            call("shutdown_pc", 3600),
            call("cancel_shutdown"),
        ]
        + [
            plat(fail=["shutdown", "cancel_shutdown"]),
            call("shutdown_pc", 5),
            call("cancel_shutdown"),
        ],
    )
    add(
        "observe_lock_transitions",
        setup(),
        [
            {"op": "observe"},
            plat(locked=True),
            {"op": "observe"},
            call("lock_pc"),
            {"op": "observe"},
            plat(locked=False),
            {"op": "observe"},
            call("lock_pc"),
            plat(fail=["lock_workstation"], locked=False),
            call("lock_pc"),
            plat(fail=["check_session_locked"]),
            {"op": "observe"},
        ],
    )
    add(
        "access_status_matrix",
        setup(
            "2026-05-17T22:00:00",
            daily={"wake_time": "07:00", "bed_time": "21:00", "allowance": 30},
        ),
        [read("access_status"), plat(locked=True), read("access_status"), call("clear_bed_time")]
        + [
            read("access_status"),
            plat(locked=False),
            read("access_status"),
            call("engage_manual_lock"),
        ]
        + [read("access_status"), call("clear_manual_lock"), call("set_daily_allowance", 1)]
        + [call("save_state"), read("access_status")],
    )

    # --- loading and state-file trouble ----------------------------------
    add("load_defaults_when_no_files", {"now": START, "files": {}}, [STEP, call("save_state")])
    add(
        "load_logs_state_applied",
        setup(
            daily={"wake_time": "06:30", "bed_time": "20:45", "allowance": 95},
            state={"accumulated": 125.5, "manual": True, "extension": 1234},
        ),
        [],
    )
    add(
        "load_extension_only_allowance",
        setup(daily={"wake_time": "07:00"}, state={"extension": 90}),
        [read("time_remaining"), call("load_state")],
    )
    add(
        "load_corrupt_state_restored_from_backup",
        setup(
            files={"state.json": "{not json", "state.json.bak": state_text(START, 600, False, 60)}
        ),
        [read("time_remaining"), call("save_state")],
    )
    add(
        "load_corrupt_daily_no_backup",
        setup(files={"daily_settings.json": "[1,2]"}),
        [read("time_remaining"), call("save_state")],
    )
    add(
        "load_failure_blocks_save_then_recovers",
        {
            "now": START,
            "files": {"state.json": state_text(START, 600)},
        },
        [
            *unreadable_daily_settings(),
            call("load_state"),
            call("set_bed_time", 20, 0),
            call("save_state"),
            call("save_state"),
            {"op": "rmdir", "name": "daily_settings.json"},
            write_daily({"wake_time": "05:00", "allowance": 30}),
            call("save_state"),
            call("save_state"),
        ],
    )
    add(
        "load_failure_blocks_monitor_persistence",
        {"now": START, "files": {"state.json": state_text(START, 600)}},
        [
            *unreadable_daily_settings(),
            call("load_state"),
            STEP,
            adv(61),
            STEP,
            adv(61),
            STEP,
        ],
    )
    add(
        "load_from_legacy_file",
        {
            "now": START,
            "files": {
                "pc_control_state.json": json.dumps(
                    {
                        "wake_time": "06:45",
                        "lock_times": ["21:15"],
                        "daily_limit_minutes": 75,
                        "minutes_used_today": 10,
                        "last_date": "2026-05-17",
                    }
                )
            },
        },
        [read("time_remaining")],
    )

    # --- log tail ---------------------------------------------------------
    def log(text: str) -> bytes:
        return text.encode("utf-8")

    def tail_case(name: str, content: bytes | None, tails: list[int]) -> None:
        steps: list[dict[str, Any]] = []
        if content is not None:
            steps.append({"op": "write_log", "hex": content.hex()})
        steps += [{"op": "read_tail", "tail": t} for t in tails]
        add(name, setup(), steps)

    tail_case("tail_missing_file", None, [1, 5])
    tail_case("tail_empty_file", b"", [1])
    tail_case("tail_only_newlines", b"\n\n\n", [1, 5])
    tail_case("tail_one_line_no_newline", b"hello", [1, 2])
    tail_case("tail_one_line_with_newline", b"hello\n", [1, 2])
    tail_case("tail_blank_lines_inside", b"a\n\nb\n\n\nc\n", [1, 2, 3, 4, 5, 6, 7])
    tail_case("tail_leading_blank_line", b"\na\nb\n", [1, 2, 3, 4])
    tail_case("tail_trailing_blank_lines_dropped", b"a\nb\n\n\n\n", [1, 2, 3])
    tail_case("tail_crlf_kept", b"a\r\nb\r\n", [1, 2, 3])
    numbered = "".join(f"line {i:04d}\n" for i in range(1, 301))
    tail_case("tail_many_lines", log(numbered), [1, 2, 50, 299, 300, 301, 5000])
    tail_case(
        "tail_exact_block_sizes",
        log("".join(f"{'x' * 99}{i % 10}\n" for i in range(84))),
        [1, 82, 83, 84, 85],
    )
    tail_case("tail_line_longer_than_block", log("first\n" + "y" * 9000 + "\nlast\n"), [1, 2, 3])
    tail_case("tail_line_spans_block_edge", log("a" * 8191 + "\n" + "b" * 8191 + "\nc\n"), [2])
    tail_case("tail_multibyte_across_blocks", log("é" * 4200 + "\nz\n"), [2])
    tail_case("tail_invalid_utf8", b"ok\n\xff\xfe bad \xc3\n\xe2\x82\nend\xe2\x82", [1, 2, 3, 4, 5])
    tail_case(
        "tail_invalid_utf8_sequences",
        b"\xf0\x9f\x98\nA\xf0\x9f\nB\xed\xa0\x80\nC\xc0\x80\nD\xf4\x90\x80\x80\nE\x80\x80\nF",
        [1, 2, 3, 4, 5, 6, 7],
    )
    tail_case(
        "tail_invalid_utf8_prefixes",
        # Valid prefixes of 3- and 4-byte sequences cut short, then plain text:
        # each is one U+FFFD.  The "bad second byte" lines are one per byte.
        b"\xed\x9fX\n\xf4\x8fX\n\xe0\xa0X\n\xf0\x90\x80X\n\xf1\x80\x80X\n\xe1\x80X\n\xc2X\n"
        b"\xe0\x9f\x80X\n\xf0\x8f\x80\x80X\n\xed\xa0\x80X\n\xf4\x90\x80\x80X\n\xf5\x80X\n\xc1\xbfX",
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    )
    tail_case("tail_zero_and_negative", log("a\nb\n"), [0])
    add(
        "tail_unreadable",
        setup(),
        [{"op": "mkdir", "name": "pc_control.log"}, {"op": "read_tail", "tail": 3}],
    )
    return out


def unreadable_daily_settings() -> list[dict[str, Any]]:
    """Ops that leave a directory where daily_settings.json (and its backup) were."""
    return [
        {"op": "delete_file", "name": "daily_settings.json"},
        {"op": "delete_file", "name": "daily_settings.json.bak"},
        {"op": "mkdir", "name": "daily_settings.json"},
    ]


def write_daily(fields: dict[str, Any]) -> dict[str, Any]:
    return {"op": "write_file", "name": "daily_settings.json", "text": json.dumps(fields)}


# ---------------------------------------------------------------------------
# Random scenarios
# ---------------------------------------------------------------------------
GAPS = [
    0.25,
    0.5,
    1,
    1,
    1,
    1,
    1,
    2,
    5,
    29.999,
    30,
    59.999999,
    60,
    61,
    90,
    300,
    1800,
    3600,
    -2,
    -3600,
    0,
]
CLOCK_STARTS = [
    "2026-05-17T06:59:30",
    "2026-05-17T12:00:00",
    "2026-05-17T20:58:00",
    "2026-05-17T22:30:00",
    "2026-05-17T23:59:00",
    "2026-05-17T03:00:00",
    "2026-03-08T01:59:00",
    "2026-12-31T23:58:30",
]


def random_scenarios(count: int = 40, length: int = 60) -> list[dict[str, Any]]:
    rng = random.Random(20261024)
    out: list[dict[str, Any]] = []
    for index in range(count):
        daily: dict[str, Any] = {
            "wake_time": rng.choice(["07:00", "06:30", "00:00", "09:15"]),
            "allowance": rng.choice([None, None, 5, 30, 40, 90, 240]),
            "bed_time": rng.choice([None, None, "21:00", "21:45", "23:30", "06:00"]),
        }
        daily = {k: v for k, v in daily.items() if v is not None}
        state = {
            "accumulated": rng.choice([0, 0, 120, 1500, 2300, 3550, 7000]),
            "manual": rng.random() < 0.15,
            "extension": rng.choice([0, 0, 0, 300, 3600]),
        }
        extra: dict[str, Any] = {}
        roll = rng.random()
        if roll < 0.12:
            extra["exempt"] = ["kid"]
        elif roll < 0.18:
            extra["monitored"] = ["other"]
        start = rng.choice(CLOCK_STARTS)
        scen_setup = setup(
            start,
            daily=daily,
            state=state,
            platform={"locked": rng.random() < 0.2, "active": rng.random() < 0.9},
            **extra,
        )
        steps: list[dict[str, Any]] = []
        for _ in range(length):
            roll = rng.random()
            if roll < 0.40:
                steps += [adv(rng.choice(GAPS)), STEP]
            elif roll < 0.55:
                steps += [adv(rng.choice(GAPS)), rng.choice([TICK, WARN, {"op": "observe"}])]
            elif roll < 0.65:
                steps.append(
                    plat(
                        locked=rng.random() < 0.4,
                        active=rng.random() < 0.8,
                        fail=rng.choice(
                            [
                                [],
                                [],
                                [],
                                ["show_message"],
                                ["lock_workstation"],
                                ["check_session_locked"],
                                ["session_is_active"],
                            ]
                        ),
                    )
                )
            elif roll < 0.92:
                steps.append(random_call(rng))
            else:
                steps.append(read(rng.choice(list(READS))))
        out.append({"name": f"random_{index:02d}", "setup": scen_setup, "steps": steps})
    return out


def random_call(rng: random.Random) -> dict[str, Any]:
    kind = rng.choice(
        [
            "set_bed_time",
            "clear_bed_time",
            "set_wake_time",
            "set_daily_allowance",
            "extend_time",
            "clear_extensions",
            "clear_warnings",
            "engage_manual_lock",
            "clear_manual_lock",
            "send_parent_message",
            "save_state",
            "shutdown_pc",
        ]
    )
    if kind == "set_bed_time":
        return call(kind, rng.choice([0, 6, 20, 21, 23]), rng.choice([0, 15, 45, 59]))
    if kind == "set_wake_time":
        return call(kind, rng.choice([0, 5, 7, 9, 12]), rng.choice([0, 30]))
    if kind == "set_daily_allowance":
        return call(kind, rng.choice([None, 1, 10, 45, 120]))
    if kind == "extend_time":
        return call(kind, rng.choice([1, 5, 15, 60]))
    if kind == "send_parent_message":
        return call(kind, rng.choice(["hi", "x" * 130]))
    if kind == "shutdown_pc":
        return call(kind, rng.choice([0, 60]))
    return call(kind)


# ---------------------------------------------------------------------------
def build_vectors() -> dict[str, Any]:
    scenarios = [run_scenario(s) for s in fixed_scenarios() + random_scenarios()]
    names = [s["name"] for s in scenarios]
    assert len(names) == len(set(names)), "duplicate scenario names"
    return {
        "_about": (
            "Golden monitoring-loop vectors generated from kid_pc_monitor.pc_time_control by "
            "tests/monitor_vectors_gen.py. Do not edit by hand."
        ),
        "log_prefix_only": LOG_PREFIX_ONLY,
        "scenarios": scenarios,
    }


def render(vectors: dict[str, Any]) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the file is out of date")
    args = parser.parse_args()
    text = render(build_vectors())
    if args.check:
        current = VECTORS_PATH.read_text(encoding="utf-8") if VECTORS_PATH.exists() else ""
        if current != text:
            print(
                f"{VECTORS_PATH} is out of date; run tests/monitor_vectors_gen.py", file=sys.stderr
            )
            return 1
        return 0
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

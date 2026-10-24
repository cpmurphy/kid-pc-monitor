"""Generate the golden request-dispatcher vectors shared by the Python and Go implementations.

Runs :func:`kid_pc_monitor.request_dispatcher.dispatch` against a deterministic
fake control object and records, for each request, the response content and the
calls made on the control.  ``testdata/dispatcher/vectors.json`` is consumed by
``go/dispatcher``; ``tests/test_dispatcher_vectors.py`` fails when it is stale.

    python tests/dispatcher_vectors_gen.py          # rewrite the vectors file
    python tests/dispatcher_vectors_gen.py --check  # exit 1 if the file is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import time as dtime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from kid_pc_monitor import agent_protocol as proto  # noqa: E402
from kid_pc_monitor.lock_policy import parse_time_hhmm  # noqa: E402
from kid_pc_monitor.request_dispatcher import dispatch  # noqa: E402
from protocol_vectors_gen import nodes_json  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "dispatcher" / "vectors.json"

DEFAULT_STATE: dict[str, Any] = {
    "hostname": "kid-pc",
    "current_user": "kid",
    "screen_locked": False,
    "allowance": 120,
    "bed_time": "21:00",
    "wake_time": "07:00",
    "manual_lock": False,
    "extension_seconds": 900,
    "accumulated_seconds": 1234.9,
    "time_remaining": 85.5,
    "enforcement": [False, None],
    "access_status": "Unlocked",
    "log_path": "C:\\ProgramData\\KidPCMonitor\\pc_control.log",
    "log_lines": ["[2026-05-31 12:00:00] INFO started", "[2026-05-31 12:00:01] INFO tick"],
    "log_truncated": False,
    "log_error": None,
}


def expand_lines(spec: Any) -> list[str]:
    """Log lines are either a literal list or a ``{"gen": ..., "count": n}`` recipe."""
    if isinstance(spec, list):
        return spec
    count = spec["count"]
    if spec["gen"] == "plain":
        return [
            f"[2026-05-31 12:00:{i % 60:02d}] INFO kid_pc_monitor: line {i} with some text"
            for i in range(count)
        ]
    if spec["gen"] == "wide":
        return ["é" * 300 + str(i) for i in range(count)]
    if spec["gen"] == "quoted":
        return [f'"{i}" \\ \t' for i in range(count)]
    raise ValueError(spec["gen"])


def _time(text: str | None) -> dtime | None:
    return None if text is None else parse_time_hhmm(text)


def _hhmm(value: dtime | None) -> str | None:
    return None if value is None else f"{value.hour:02d}:{value.minute:02d}"


class FakeControl:
    """The part of PCTimeControl the dispatcher touches, with recorded calls."""

    def __init__(self, state: dict[str, Any]) -> None:
        self.calls: list[list[Any]] = []
        self._state = {**state, "log_lines": expand_lines(state["log_lines"])}
        self.platform = SimpleNamespace(get_hostname=lambda: state["hostname"])
        self.current_user = state["current_user"]
        self.daily = SimpleNamespace(
            allowance=state["allowance"],
            bed_time=_time(state["bed_time"]),
            wake_time=_time(state["wake_time"]),
        )
        self.runtime = SimpleNamespace(
            manual_lock_active=state["manual_lock"],
            cumulative_extension_seconds=state["extension_seconds"],
            accumulated_seconds=state["accumulated_seconds"],
        )
        self.agent_log_path = state["log_path"]
        self.warnings_sent = SimpleNamespace(clear=lambda: self.calls.append(["clear_warnings"]))

    # --- reads ---------------------------------------------------------------
    def check_if_locked(self) -> bool:
        return self._state["screen_locked"]

    def get_time_remaining(self) -> float | None:
        return self._state["time_remaining"]

    def enforcement_lock_state(self) -> tuple[bool, str | None]:
        active, reason = self._state["enforcement"]
        return active, reason

    def get_access_status(self) -> str:
        return self._state["access_status"]

    def read_log_tail(self, *, tail: int) -> tuple[list[str], bool]:
        self.calls.append(["read_log_tail", tail])
        if self._state["log_error"] is not None:
            raise OSError(self._state["log_error"])
        lines = self._state["log_lines"]
        return lines[-tail:], self._state["log_truncated"] or len(lines) > tail

    # --- actions ---------------------------------------------------------------
    def set_daily_allowance(self, minutes: int | None) -> None:
        self.calls.append(["set_daily_allowance", minutes])
        self.daily.allowance = minutes

    def set_bed_time(self, hour: int, minute: int) -> None:
        self.calls.append(["set_bed_time", hour, minute])
        self.daily.bed_time = dtime(hour, minute)

    def clear_bed_time(self) -> None:
        self.calls.append(["clear_bed_time"])
        self.daily.bed_time = None

    def set_wake_time(self, hour: int, minute: int) -> None:
        self.calls.append(["set_wake_time", hour, minute])
        self.daily.wake_time = dtime(hour, minute)

    def engage_manual_lock(self) -> None:
        self.calls.append(["engage_manual_lock"])
        self.runtime.manual_lock_active = True

    def clear_manual_lock(self) -> None:
        self.calls.append(["clear_manual_lock"])
        self.runtime.manual_lock_active = False

    def clear_extensions(self) -> None:
        self.calls.append(["clear_extensions"])
        self.runtime.cumulative_extension_seconds = 0

    def extend_time(self, minutes: int) -> None:
        self.calls.append(["extend_time", minutes])
        self.runtime.cumulative_extension_seconds += minutes * 60
        self.runtime.manual_lock_active = False

    def send_parent_message(self, message: str) -> None:
        self.calls.append(["send_parent_message", message])

    def shutdown_pc(self, seconds: int = 60) -> None:
        self.calls.append(["shutdown_pc", seconds])

    def save_state(self) -> None:
        self.calls.append(["save_state"])


def run(name: str, request: dict[str, Any], **state: Any) -> dict[str, Any]:
    full_state = {**DEFAULT_STATE, **state}
    fake = FakeControl(full_state)
    req = proto.Request(
        request.get("version", proto.CLIENT_DEFAULT_VERSION),
        request.get("id", "r1"),
        request["action"],
        request.get("var"),
        request.get("val"),
        name=request.get("name", "kid-pc"),
        tail=request.get("tail"),
    )
    case: dict[str, Any] = {"name": name, "state": state, "request": {**request}}
    try:
        case["content"] = nodes_json(dispatch(fake, req))
    except proto.ProtocolError as exc:
        case["error"] = {"code": exc.code, "message": exc.message, "req_id": exc.req_id}
    case["calls"] = fake.calls
    case["after"] = {
        "allowance": fake.daily.allowance,
        "bed_time": _hhmm(fake.daily.bed_time),
        "wake_time": _hhmm(fake.daily.wake_time),
        "manual_lock": fake.runtime.manual_lock_active,
        "extension_seconds": fake.runtime.cumulative_extension_seconds,
    }
    return case


def get(var: str | None, **state: Any) -> dict[str, Any]:
    return {"action": "get", "var": var, **({"state": state} if state else {})}


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    def add(name: str, request: dict[str, Any], **state: Any) -> None:
        cases.append(run(name, request, **state))

    # --- get ---------------------------------------------------------------------
    for var in proto.VARIABLES:
        add(f"get_{var}", {"action": "get", "var": var})
    add("get_settings", {"action": "get", "var": "settings"})
    add(
        "get_settings_everything_set_and_locked",
        {"action": "get", "var": "settings"},
        screen_locked=True,
        manual_lock=True,
        allowance=45,
        bed_time="22:15",
        enforcement=[True, "past bedtime"],
        access_status="Locked — past bedtime",
        time_remaining=0,
    )
    add(
        "get_settings_nothing_set",
        {"action": "get", "var": "settings"},
        allowance=None,
        bed_time=None,
        extension_seconds=0,
        accumulated_seconds=0.0,
        time_remaining=None,
    )
    add("get_name_unicode", {"action": "get", "var": "name"}, hostname="Kinder-PC ü")
    add("get_status_locked", {"action": "get", "var": "status"}, screen_locked=True)
    add("get_daily_limit_none", {"action": "get", "var": "daily_limit"}, allowance=None)
    add("get_bed_time_none", {"action": "get", "var": "bed_time"}, bed_time=None)
    add("get_manual_lock_true", {"action": "get", "var": "manual_lock"}, manual_lock=True)
    for remaining in (None, 0, 0.4, 0.5, 1.5, 2.5, 3.5, 89.999, 90.5, -0.5, 1440.49):
        add(
            f"get_time_remaining_{remaining}",
            {"action": "get", "var": "time_remaining"},
            time_remaining=remaining,
        )
    for acc in (0.0, 0.99, 59.999, 1234.9, 86400.5):
        add(
            f"get_accumulated_{acc}",
            {"action": "get", "var": "accumulated_seconds"},
            accumulated_seconds=acc,
        )
    add("get_extension", {"action": "get", "var": "cumulative_extension"}, extension_seconds=3600)
    add(
        "get_enforcement_reason_active",
        {"action": "get", "var": "enforcement_reason"},
        enforcement=[True, "daily limit reached"],
    )
    add(
        "get_enforcement_reason_hidden_when_inactive",
        {"action": "get", "var": "enforcement_reason"},
        enforcement=[False, "stale reason"],
    )
    add(
        "get_enforcement_active",
        {"action": "get", "var": "enforcement_active"},
        enforcement=[True, "before wake-up"],
    )
    add("get_unknown_variable", {"action": "get", "var": "nope"})
    add("get_no_variable", {"action": "get", "var": None})
    add("get_unknown_variable_keeps_no_id", {"action": "get", "var": "nope", "id": None})

    # --- set ---------------------------------------------------------------------
    for val in (
        1,
        90,
        1440,
        "90",
        " 90 ",
        "+5",
        0,
        1441,
        -5,
        "1_0",
        "٩٠",
        "9.5",
        "",
        "abc",
        True,
        False,
        None,
        2**60,
        "9" * 30,
    ):
        add(f"set_daily_limit_{val!r}", {"action": "set", "var": "daily_limit", "val": val})
    for var in ("bed_time", "wake_time"):
        for val in (
            "21:30",
            "9:05",
            " 07:00 ",
            "00:00",
            "23:59",
            "24:00",
            "7:5",
            "07:00:00",
            "bad",
            "",
            730,
            True,
            None,
            "５:00",
        ):
            add(f"set_{var}_{val!r}", {"action": "set", "var": var, "val": val})
    for val in (
        True,
        False,
        "true",
        "TRUE",
        " Yes ",
        "1",
        1,
        "false",
        "No",
        "0",
        0,
        "maybe",
        "",
        2,
        "2",
        None,
        "٣",
    ):
        add(f"set_manual_lock_{val!r}", {"action": "set", "var": "manual_lock", "val": val})
    for var in ("name", "status", "current_user", "cumulative_extension", "nope"):
        add(f"set_{var}_is_refused", {"action": "set", "var": var, "val": 1})

    # --- clear ---------------------------------------------------------------------
    for var in ("daily_limit", "bed_time", "cumulative_extension", "manual_lock"):
        add(f"clear_{var}", {"action": "clear", "var": var}, manual_lock=True)
    for var in ("name", "wake_time", "accumulated_seconds", "nope"):
        add(f"clear_{var}_is_refused", {"action": "clear", "var": var})

    # --- extend, message, shutdown, lock ---------------------------------------------
    for val in (1, 15, 1440, "15", " 15 ", 0, -5, 1441, "x", "1_5", "1.5", True, None):
        add(f"extend_{val!r}", {"action": "extend", "val": val}, manual_lock=True)
    for val in ("Dinner time!", 'Dinner 🍝\nsay "hi"\t\\', "trailing\n", "  ", "", None, 5, True):
        add(f"message_{val!r}", {"action": "message", "val": val})
    for val in (None, 0, 30, 3600, "45", -1, "-1", "x", True, "1_0"):
        add(f"shutdown_{val!r}", {"action": "shutdown", "val": val})
    add("lock", {"action": "lock"})
    add("unlock", {"action": "unlock"}, manual_lock=True)
    add("list_capabilities", {"action": "list_capabilities"})
    add("unknown_action", {"action": "reboot"})
    add(
        "request_id_is_echoed_in_errors", {"action": "set", "var": "name", "val": 1, "id": "abc123"}
    )

    # --- get_logs ---------------------------------------------------------------------
    add("get_logs_default", {"action": "get_logs"})
    add("get_logs_tail_1", {"action": "get_logs", "tail": 1})
    add("get_logs_tail_larger_than_log", {"action": "get_logs", "tail": 500})
    add("get_logs_empty", {"action": "get_logs"}, log_lines=[])
    add("get_logs_already_truncated", {"action": "get_logs"}, log_truncated=True)
    add("get_logs_unreadable", {"action": "get_logs"}, log_error="disk on fire")
    add(
        "get_logs_unicode_and_quotes",
        {"action": "get_logs"},
        log_lines=['quote " and \\ backslash', "ünï 🍝", "true", "123", "", "a\tb\n"],
    )
    plain = [
        f"[2026-05-31 12:00:{i % 60:02d}] INFO kid_pc_monitor: line {i} with some text"
        for i in range(5000)
    ]
    add(
        "get_logs_5000_lines_are_cut_to_fit_the_frame",
        {"action": "get_logs", "tail": 5000},
        log_lines=plain,
    )
    add("get_logs_default_tail_fits", {"action": "get_logs"}, log_lines=plain)
    wide = {"gen": "wide", "count": 300}
    add("get_logs_wide_lines_are_cut", {"action": "get_logs", "tail": 300}, log_lines=wide)
    add(
        "get_logs_quoted_lines_cost_more",
        {"action": "get_logs", "tail": 5000},
        log_lines={"gen": "quoted", "count": 6000},
    )
    add("get_logs_huge_path_drops_everything", {"action": "get_logs"}, log_path="p" * 70000)
    add("get_logs_one_enormous_line", {"action": "get_logs"}, log_lines=["x" * 70000, "small"])
    return cases


def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden request-dispatcher vectors generated from kid_pc_monitor.request_dispatcher "
            "by tests/dispatcher_vectors_gen.py. Do not edit by hand."
        ),
        "default_state": DEFAULT_STATE,
        "constants": {
            "min_daily_limit": proto.MIN_DAILY_LIMIT,
            "max_daily_limit": proto.MAX_DAILY_LIMIT,
            "default_shutdown_seconds": proto.DEFAULT_SHUTDOWN_SECONDS,
            "default_log_tail_lines": proto.DEFAULT_LOG_TAIL_LINES,
            "max_frame_bytes": proto.MAX_FRAME_BYTES,
            "writable_variables": sorted(proto.WRITABLE_VARIABLES),
            "clearable_variables": sorted(proto.CLEARABLE_VARIABLES),
        },
        "cases": build_cases(),
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
                f"{VECTORS_PATH} is out of date; run tests/dispatcher_vectors_gen.py",
                file=sys.stderr,
            )
            return 1
        return 0
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Generate the golden agent-state vectors shared by the Python and Go implementations.

A snapshot of :mod:`kid_pc_monitor.agent_state` for a fixed set of inputs,
written to ``testdata/state/vectors.json``.  ``go/state`` must reproduce every
case; ``tests/test_state_vectors.py`` fails when the file is stale.

    python tests/state_vectors_gen.py          # rewrite the vectors file
    python tests/state_vectors_gen.py --check  # exit 1 if the file is stale

Inputs that Python rejects with an exception record the exception's class name
(``ValueError`` and ``TypeError`` are distinguished because the store reacts to
them differently).  Datetimes are naive wall-clock ISO strings.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kid_pc_monitor import agent_state as st  # noqa: E402
from kid_pc_monitor.lock_policy import parse_time_hhmm  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "state" / "vectors.json"
ALLOWED_ERRORS = {"ValueError", "TypeError"}

NOW = "2026-05-17T10:00:00"


def hhmm(value: dtime | None) -> str | None:
    return None if value is None else f"{value.hour:02d}:{value.minute:02d}"


def tod(text: str) -> dtime:
    return parse_time_hhmm(text)


def daily_json(daily: st.DailySettings) -> dict[str, Any]:
    return {
        "bed_time": hhmm(daily.bed_time),
        "wake_time": hhmm(daily.wake_time),
        "allowance": daily.allowance,
    }


def runtime_json(runtime: st.RuntimeState) -> dict[str, Any]:
    return {
        # Offsets are dropped: only the wall-clock fields matter to the agent.
        "timestamp": runtime.timestamp.replace(tzinfo=None).isoformat(),
        "accumulated_seconds": runtime.accumulated_seconds,
        "manual_lock_active": runtime.manual_lock_active,
        "cumulative_extension_seconds": runtime.cumulative_extension_seconds,
    }


def outcome(fn: Any) -> dict[str, Any]:
    """Run ``fn`` and return ``{"ok": ...}`` or ``{"error": <class name>}``."""
    try:
        return {"ok": fn()}
    except Exception as exc:
        name = type(exc).__name__
        assert name in ALLOWED_ERRORS, f"unexpected {name}: {exc}"
        return {"error": name}


def make_runtime(
    timestamp: str, acc: float = 0.0, manual: bool = False, ext: int = 0
) -> st.RuntimeState:
    return st.RuntimeState(datetime.fromisoformat(timestamp), acc, manual, ext)


def make_daily(bed: str | None, wake: str, allowance: int | None) -> st.DailySettings:
    return st.DailySettings(None if bed is None else tod(bed), tod(wake), allowance)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def effective_allowance_cases() -> list[dict[str, Any]]:
    cases = []
    for allowance in (None, 0, 60, 90):
        for ext in (-60, 0, 1, 60, 90, 1800):
            result = st.effective_daily_allowance_minutes(
                make_daily(None, "07:00", allowance), make_runtime(NOW, ext=ext)
            )
            cases.append({"allowance": allowance, "extension_seconds": ext, "result": result})
    return cases


TIMESTAMPS = [
    "2026-05-17T06:59:59",
    "2026-05-17T07:00:00",
    "2026-05-16T23:59:59",
    "2026-05-16T07:00:00",
    "2026-05-10T12:00:00",
    "2025-12-31T23:00:00",
]
NOWS = ["2026-05-17T06:00:00", "2026-05-17T07:00:00", "2026-05-17T15:30:00", "2026-05-18T06:59:59"]
WAKES = ["07:00", "00:00", "12:00"]


def rollover_cases() -> list[dict[str, Any]]:
    cases = []
    for ts in TIMESTAMPS:
        for now in NOWS:
            for wake in WAKES:
                runtime = make_runtime(ts, acc=1234.5, manual=True, ext=900)
                current = st.runtime_state_is_current(
                    runtime, tod(wake), datetime.fromisoformat(now)
                )
                changed = st.reset_runtime_if_needed(
                    runtime, tod(wake), datetime.fromisoformat(now)
                )
                cases.append(
                    {
                        "timestamp": ts,
                        "now": now,
                        "wake": wake,
                        "current": current,
                        "changed": changed,
                        "after": runtime_json(runtime),
                    }
                )
    return cases


def to_dict_cases() -> dict[str, list[dict[str, Any]]]:
    dailies = [
        (None, "07:00", None),
        ("21:00", "06:30", 120),
        ("00:00", "00:00", 0),
        ("23:59", "12:00", 1440),
    ]
    runtimes = [
        ("2026-05-17T10:00:00", 0.0, False, 0),
        ("2026-05-17T10:00:00.999999", 1234.56789, True, 900),
        ("2026-05-17T10:00:00.5", 0.0005, False, -60),
        ("2026-05-17T10:00:00", 0.0015, False, 0),
        ("2026-05-17T10:00:00", 59.9996, False, 0),
        ("2026-05-17T10:00:00", 86399.12345, False, 1),
        ("2026-05-17T10:00:00", 1e-07, False, 0),
        ("2026-05-17T10:00:00", 2.5, False, 0),
    ]
    return {
        "daily": [
            {
                "in": {"bed_time": b, "wake_time": w, "allowance": a},
                "out": st.daily_to_dict(make_daily(b, w, a)),
            }
            for b, w, a in dailies
        ],
        "runtime": [
            {
                "in": {
                    "timestamp": ts,
                    "accumulated_seconds": acc,
                    "manual_lock_active": manual,
                    "cumulative_extension_seconds": ext,
                },
                "out": st.runtime_to_dict(make_runtime(ts, acc, manual, ext)),
            }
            for ts, acc, manual, ext in runtimes
        ],
    }


DAILY_DICTS: list[dict[str, Any]] = [
    {},
    {"wake_time": "06:30", "bed_time": "21:00", "allowance": 120},
    {"wake_time": "6:5", "bed_time": "9:00", "allowance": 1},
    {"bed_time": ""},
    {"bed_time": None},
    {"bed_time": None, "allowance": None, "wake_time": "07:00"},
    {"allowance": "90"},
    {"allowance": " 12 "},
    {"allowance": 90.7},
    {"allowance": -5.9},
    {"allowance": 1e3},
    {"allowance": True},
    {"allowance": False},
    {"allowance": 0},
    {"allowance": "abc"},
    {"allowance": "1.5"},
    {"allowance": ""},
    {"allowance": []},
    {"allowance": {}},
    {"wake_time": None},
    {"wake_time": 7},
    {"wake_time": 7.5},
    {"wake_time": True},
    {"wake_time": ["07:00"]},
    {"wake_time": ""},
    {"wake_time": "25:00"},
    {"wake_time": "7"},
    {"bed_time": 0},
    {"bed_time": False},
    {"bed_time": "nope"},
    {"bed_time": "21:00", "extra": 1, "target_user": "kid"},
    {"wake_time": "08:00", "bed_time": "21:30", "allowance": 45, "target_user": "Kid"},
]

COMPLETE_EXTRA: list[dict[str, Any]] = [
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": 120},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": None},
    {"wake_time": "07:00", "bed_time": "21:00"},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": 0},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": -5},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": "30"},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": "x"},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": []},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": 0.5},
    {"wake_time": "07:00", "bed_time": "21:00", "allowance": True},
    {"wake_time": "07:00", "bed_time": None, "allowance": 60},
    {"wake_time": "07:00", "bed_time": "", "allowance": 60},
    {"wake_time": "", "bed_time": "21:00", "allowance": 60},
    {"bed_time": "21:00", "allowance": 60},
    {"wake_time": "07:00", "bed_time": "bad", "allowance": 60},
    {"wake_time": "bad", "bed_time": "21:00", "allowance": 60},
    {"wake_time": 700, "bed_time": "21:00", "allowance": 60},
    {"wake_time": "07:00", "bed_time": 2100, "allowance": 60},
    {"wake_time": [], "bed_time": "21:00", "allowance": 60},
]


def load_daily_cases() -> list[dict[str, Any]]:
    return [
        {"in": data, **outcome(lambda d=data: daily_json(st.load_daily_from_dict(d)))}
        for data in DAILY_DICTS
    ]


def complete_daily_cases() -> list[dict[str, Any]]:
    return [
        {"in": data, "result": st.is_complete_daily_dict(data)}
        for data in [*DAILY_DICTS, *COMPLETE_EXTRA]
    ]


RUNTIME_DICTS: list[dict[str, Any]] = [
    {},
    {"timestamp": None},
    {"timestamp": 5},
    {"timestamp": ""},
    {"timestamp": "garbage"},
    {"timestamp": NOW},
    {"timestamp": "2026-05-17 10:00:00"},
    {"timestamp": "2026-05-17T10:00"},
    {"timestamp": "2026-05-17T10"},
    {"timestamp": "2026-05-17"},
    {"timestamp": "2026-05-17T10:00:00.123456"},
    {"timestamp": "2026-05-17T10:00:00.5"},
    {"timestamp": "2026-05-17T10:00:00,5"},
    {"timestamp": "2026-05-17T10:00:00.1234567"},
    {"timestamp": "2026-05-17T10:00:00+02:00"},
    {"timestamp": "2026-05-17T10:00:00-0530"},
    {"timestamp": "2026-05-17T10:00:00Z"},
    {"timestamp": "2026-05-17T10:00:00.25+00:00"},
    {"timestamp": "2026-13-01T00:00:00"},
    {"timestamp": "2026-02-30T00:00:00"},
    {"timestamp": "2024-02-29T23:59:59"},
    {"timestamp": "2026-05-17T10:60:00"},
    {"timestamp": "2026-05-17T10:00:60"},
    {"timestamp": "2026-05-17T10:00:00 "},
    {"timestamp": "26-05-17T10:00:00"},
    {"timestamp": NOW, "accumulated_seconds": 12.5},
    {"timestamp": NOW, "accumulated_seconds": 7},
    {"timestamp": NOW, "accumulated_seconds": "12.5"},
    {"timestamp": NOW, "accumulated_seconds": " 3 "},
    {"timestamp": NOW, "accumulated_seconds": True},
    {"timestamp": NOW, "accumulated_seconds": "abc"},
    {"timestamp": NOW, "accumulated_seconds": ""},
    {"timestamp": NOW, "accumulated_seconds": None},
    {"timestamp": NOW, "accumulated_seconds": []},
    {"timestamp": NOW, "manual_lock_active": True},
    {"timestamp": NOW, "manual_lock_active": "yes"},
    {"timestamp": NOW, "manual_lock_active": ""},
    {"timestamp": NOW, "manual_lock_active": "false"},
    {"timestamp": NOW, "manual_lock_active": 0},
    {"timestamp": NOW, "manual_lock_active": 2},
    {"timestamp": NOW, "manual_lock_active": 0.0},
    {"timestamp": NOW, "manual_lock_active": None},
    {"timestamp": NOW, "manual_lock_active": []},
    {"timestamp": NOW, "manual_lock_active": [0]},
    {"timestamp": NOW, "manual_lock_active": {}},
    {"timestamp": NOW, "manual_lock_active": {"a": 1}},
    {"timestamp": NOW, "cumulative_extension_seconds": 900},
    {"timestamp": NOW, "cumulative_extension_seconds": "30"},
    {"timestamp": NOW, "cumulative_extension_seconds": 30.9},
    {"timestamp": NOW, "cumulative_extension_seconds": -30.9},
    {"timestamp": NOW, "cumulative_extension_seconds": True},
    {"timestamp": NOW, "cumulative_extension_seconds": "x"},
    {"timestamp": NOW, "cumulative_extension_seconds": "1.5"},
    {"timestamp": NOW, "cumulative_extension_seconds": None},
    {"timestamp": NOW, "cumulative_extension_seconds": {}},
]


def load_runtime_cases() -> list[dict[str, Any]]:
    return [
        {"in": data, **outcome(lambda d=data: runtime_json(st.load_runtime_from_dict(d)))}
        for data in RUNTIME_DICTS
    ]


LEGACY_DICTS: list[dict[str, Any]] = [
    {},
    {
        "wake_time": "06:00",
        "lock_times": ["21:30"],
        "usage_allowance": 90,
        "accumulated_seconds": 600,
        "manual_lock_active": True,
    },
    {"accumulated_seconds": 600, "manual_lock_active": True, "accumulated_date": "2026-05-17"},
    {"accumulated_seconds": 600, "manual_lock_active": True, "accumulated_date": "2026-05-16"},
    {"accumulated_seconds": 600, "manual_lock_active": True, "accumulated_date": "2026-05-15"},
    {"accumulated_seconds": 600, "accumulated_date": "2026-05-18"},
    {
        "accumulated_seconds": 600,
        "manual_lock_active": True,
        "accumulated_date": "2026-05-16",
        "wake_time": "12:00",
    },
    {"accumulated_date": "garbage"},
    {"accumulated_date": ""},
    {"accumulated_date": 5},
    {"accumulated_date": None},
    {"lock_times": []},
    {"lock_times": None},
    {"lock_times": ["21:30", "22:00"]},
    {"lock_times": ["nope"]},
    {"lock_times": [5]},
    {"lock_times": [None, "21:00"]},
    {"lock_times": ["25:00"]},
    {"lock_times": ["9:05"]},
    {"lock_times": "21:30"},
    {"lock_times": ":"},
    {"lock_times": 5},
    {"lock_times": 0},
    {"lock_times": True},
    {"wake_time": 7},
    {"wake_time": None},
    {"wake_time": "bad"},
    {"wake_time": "6:30"},
    {"usage_allowance": "45"},
    {"usage_allowance": None},
    {"usage_allowance": 45.9},
    {"usage_allowance": []},
    {"usage_allowance": "x"},
    {"accumulated_seconds": "12.5"},
    {"accumulated_seconds": None},
    {"accumulated_seconds": "abc"},
    {"manual_lock_active": "no"},
    {"manual_lock_active": 0},
]


def legacy_cases() -> list[dict[str, Any]]:
    cases = []
    for data in LEGACY_DICTS:

        def run(d: dict[str, Any] = data) -> dict[str, Any]:
            daily, runtime = st.legacy_to_state(d, now=datetime.fromisoformat(NOW))
            return {"daily": daily_json(daily), "runtime": runtime_json(runtime)}

        cases.append({"in": data, "now": NOW, **outcome(run)})
    return cases


# ---------------------------------------------------------------------------
# Store scenarios (files in, files out)
# ---------------------------------------------------------------------------
def dumps(obj: Any) -> str:
    return json.dumps(obj)


DAILY_OK = dumps({"wake_time": "07:00", "allowance": 120, "bed_time": "21:00"})
STATE_NOW = dumps(
    {
        "timestamp": "2026-05-17T09:00:00",
        "accumulated_seconds": 600.5,
        "manual_lock_active": True,
        "cumulative_extension_seconds": 900,
    }
)
STATE_YESTERDAY = dumps(
    {
        "timestamp": "2026-05-16T20:00:00",
        "accumulated_seconds": 3000.0,
        "manual_lock_active": True,
        "cumulative_extension_seconds": 600,
    }
)
LEGACY = dumps(
    {
        "wake_time": "06:30",
        "lock_times": ["21:15"],
        "usage_allowance": 90,
        "accumulated_seconds": 300,
        "manual_lock_active": True,
        "accumulated_date": "2026-05-17",
    }
)

SCENARIOS: list[dict[str, Any]] = [
    {"name": "empty_dir_writes_defaults", "files": {}},
    {
        "name": "settings_and_state_load_as_is",
        "files": {"daily_settings.json": DAILY_OK, "state.json": STATE_NOW},
    },
    {
        "name": "state_from_yesterday_resets_in_memory",
        "files": {"daily_settings.json": DAILY_OK, "state.json": STATE_YESTERDAY},
    },
    {
        "name": "state_from_yesterday_before_wake_still_current",
        "now": "2026-05-17T06:00:00",
        "files": {"daily_settings.json": DAILY_OK, "state.json": STATE_YESTERDAY},
    },
    {"name": "state_missing_gives_fresh_runtime", "files": {"daily_settings.json": DAILY_OK}},
    {
        "name": "state_without_timestamp_starts_fresh",
        "files": {"daily_settings.json": DAILY_OK, "state.json": dumps({"accumulated_seconds": 5})},
    },
    {
        "name": "state_with_bad_timestamp_starts_fresh",
        "files": {"daily_settings.json": DAILY_OK, "state.json": dumps({"timestamp": "garbage"})},
    },
    {
        "name": "state_with_bad_number_is_a_value_error_so_starts_fresh",
        "files": {
            "daily_settings.json": DAILY_OK,
            "state.json": dumps({"timestamp": "2026-05-17T09:00:00", "accumulated_seconds": "x"}),
        },
    },
    {
        "name": "state_with_null_number_is_a_type_error_and_aborts",
        "files": {
            "daily_settings.json": DAILY_OK,
            "state.json": dumps(
                {"timestamp": "2026-05-17T09:00:00", "cumulative_extension_seconds": None}
            ),
        },
    },
    {
        "name": "state_not_json_is_treated_as_missing",
        "files": {"daily_settings.json": DAILY_OK, "state.json": "{not json"},
    },
    {
        "name": "state_utf8_bom_is_treated_as_missing",
        "files": {"daily_settings.json": DAILY_OK, "state.json": "﻿" + STATE_NOW},
    },
    {
        "name": "daily_not_json_is_overwritten_with_defaults",
        "files": {"daily_settings.json": "{oops", "state.json": STATE_NOW},
    },
    {
        "name": "daily_with_bad_time_aborts",
        "files": {"daily_settings.json": dumps({"wake_time": "25:00"}), "state.json": STATE_NOW},
    },
    {
        "name": "daily_with_list_allowance_aborts_with_type_error",
        "files": {"daily_settings.json": dumps({"allowance": []}), "state.json": STATE_NOW},
    },
    {
        "name": "daily_partial_uses_defaults",
        "files": {"daily_settings.json": dumps({"allowance": "75"}), "state.json": STATE_NOW},
    },
    {
        "name": "legacy_migrates_when_nothing_else_exists",
        "files": {"pc_control_state.json": LEGACY},
    },
    {
        "name": "legacy_with_stale_date_resets_usage",
        "files": {
            "pc_control_state.json": dumps(
                {
                    "usage_allowance": 60,
                    "accumulated_seconds": 900,
                    "manual_lock_active": True,
                    "accumulated_date": "2026-05-10",
                }
            )
        },
    },
    {
        "name": "legacy_invalid_aborts",
        "files": {"pc_control_state.json": dumps({"wake_time": "bad"})},
    },
    {
        "name": "legacy_not_json_is_ignored",
        "files": {"pc_control_state.json": "garbage"},
    },
    {
        "name": "legacy_overwrites_daily_when_only_state_is_missing",
        "files": {"daily_settings.json": DAILY_OK, "pc_control_state.json": LEGACY},
    },
    {
        "name": "legacy_beats_program_data",
        "files": {"pc_control_state.json": LEGACY},
        "program_data": {
            "daily_settings.json": dumps(
                {"wake_time": "08:30", "bed_time": "20:00", "allowance": 30}
            )
        },
    },
    {
        "name": "program_data_bootstraps",
        "files": {},
        "program_data": {
            "daily_settings.json": dumps(
                {"wake_time": "08:30", "bed_time": "20:00", "allowance": 30}
            )
        },
    },
    {
        "name": "program_data_target_user_matches_ignoring_case",
        "user": "Kid",
        "files": {},
        "program_data": {
            "daily_settings.json": dumps({"target_user": "kID", "wake_time": "08:30"})
        },
    },
    {
        "name": "program_data_target_user_mismatch_is_skipped",
        "user": "parent",
        "files": {},
        "program_data": {
            "daily_settings.json": dumps({"target_user": "kid", "wake_time": "08:30"})
        },
    },
    {
        "name": "program_data_empty_target_user_applies_to_everyone",
        "files": {},
        "program_data": {"daily_settings.json": dumps({"target_user": "", "wake_time": "08:30"})},
    },
    {
        "name": "program_data_invalid_value_falls_through",
        "files": {},
        "program_data": {"daily_settings.json": dumps({"wake_time": "nope"})},
    },
    {
        "name": "program_data_type_error_aborts",
        "files": {},
        "program_data": {"daily_settings.json": dumps({"allowance": {}})},
    },
    {
        "name": "program_data_not_json_falls_through",
        "files": {},
        "program_data": {"daily_settings.json": "{"},
    },
    {
        "name": "legacy_install_config_gives_wake_time_only",
        "files": {},
        "program_data": {
            "install_config.json": dumps({"wake_time": "06:45", "target_user": "kid"})
        },
    },
    {
        "name": "legacy_install_config_for_other_user_is_ignored",
        "user": "parent",
        "files": {},
        "program_data": {
            "install_config.json": dumps({"wake_time": "06:45", "target_user": "kid"})
        },
    },
    {
        "name": "legacy_install_config_bad_wake_time_is_ignored",
        "files": {},
        "program_data": {"install_config.json": dumps({"wake_time": "6:99"})},
    },
    {
        "name": "program_data_daily_beats_install_config",
        "files": {},
        "program_data": {
            "daily_settings.json": dumps({"wake_time": "08:30"}),
            "install_config.json": dumps({"wake_time": "06:45"}),
        },
    },
    {
        "name": "no_program_data_directory",
        "files": {},
        "program_data": None,
    },
    {
        "name": "save_writes_both_files_with_clock_timestamp",
        "op": "save",
        "files": {},
        "save_daily": {"bed_time": "21:15", "wake_time": "06:30", "allowance": 100},
        "save_runtime": {
            "timestamp": "2000-01-01T00:00:00",
            "accumulated_seconds": 1234.56789,
            "manual_lock_active": True,
            "cumulative_extension_seconds": 300,
        },
    },
    {
        "name": "save_without_bed_time_or_allowance",
        "op": "save",
        "files": {"daily_settings.json": DAILY_OK},
        "save_daily": {"bed_time": None, "wake_time": "07:00", "allowance": None},
        "save_runtime": {
            "timestamp": "2000-01-01T00:00:00",
            "accumulated_seconds": 0.0,
            "manual_lock_active": False,
            "cumulative_extension_seconds": 0,
        },
    },
]


def read_tree(directory: Path) -> dict[str, Any]:
    tree: dict[str, Any] = {}
    for path in sorted(directory.iterdir()) if directory.is_dir() else []:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        try:
            tree[path.name] = json.loads(text)
        except json.JSONDecodeError:
            tree[path.name] = {"_raw": text}
    return tree


def run_scenario(spec: dict[str, Any]) -> dict[str, Any]:
    now = spec.get("now", NOW)
    user = spec.get("user", "kid")
    program_data = spec.get("program_data", {})
    case: dict[str, Any] = {
        "name": spec["name"],
        "op": spec.get("op", "load"),
        "user": user,
        "now": now,
        "files": spec["files"],
        "program_data": program_data,
    }
    if case["op"] == "save":
        case["save_daily"] = spec["save_daily"]
        case["save_runtime"] = spec["save_runtime"]

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        data_dir = root / "data"
        data_dir.mkdir()
        for name, text in spec["files"].items():
            (data_dir / name).write_text(text, encoding="utf-8")
        pd_dir: Path | None = None
        if program_data is not None:
            pd_dir = root / "ProgramData" / "KidPCMonitor"
            pd_dir.mkdir(parents=True)
            for name, text in program_data.items():
                (pd_dir / name).write_text(text, encoding="utf-8")

        store = st.AgentStateStore(
            data_dir,
            current_user=user,
            clock=lambda: datetime.fromisoformat(now),
            program_data_dir=pd_dir,
        )

        def run() -> dict[str, Any]:
            if case["op"] == "save":
                d = spec["save_daily"]
                r = spec["save_runtime"]
                store.save(
                    make_daily(d["bed_time"], d["wake_time"], d["allowance"]),
                    make_runtime(
                        r["timestamp"],
                        r["accumulated_seconds"],
                        r["manual_lock_active"],
                        r["cumulative_extension_seconds"],
                    ),
                )
                return {}
            daily, runtime = store.load()
            return {"daily": daily_json(daily), "runtime": runtime_json(runtime)}

        case.update(outcome(run))
        case["files_after"] = read_tree(data_dir)
    return case


def store_cases() -> list[dict[str, Any]]:
    return [run_scenario(spec) for spec in SCENARIOS]


# ---------------------------------------------------------------------------
# Installer helpers
# ---------------------------------------------------------------------------
def installer_helper_cases() -> list[dict[str, Any]]:
    layouts: list[tuple[str, dict[str, str | None], dict[str, str | None]]] = [
        ("neither", {}, {}),
        (
            "profile_complete",
            {
                "daily_settings.json": dumps(
                    {"wake_time": "07:00", "bed_time": "21:00", "allowance": 60}
                )
            },
            {},
        ),
        (
            "profile_incomplete_program_data_complete",
            {"daily_settings.json": dumps({"wake_time": "07:00", "allowance": 60})},
            {
                "daily_settings.json": dumps(
                    {
                        "wake_time": "08:00",
                        "bed_time": "20:00",
                        "allowance": 45,
                        "target_user": "kid",
                    }
                )
            },
        ),
        (
            "both_complete_profile_wins",
            {
                "daily_settings.json": dumps(
                    {"wake_time": "07:00", "bed_time": "21:00", "allowance": 60}
                )
            },
            {
                "daily_settings.json": dumps(
                    {"wake_time": "08:00", "bed_time": "20:00", "allowance": 45}
                )
            },
        ),
        (
            "profile_unreadable_program_data_complete",
            {"daily_settings.json": "{"},
            {
                "daily_settings.json": dumps(
                    {"wake_time": "08:00", "bed_time": "20:00", "allowance": 45}
                )
            },
        ),
        (
            "complete_but_invalid_time",
            {
                "daily_settings.json": dumps(
                    {"wake_time": "07:00", "bed_time": "99:99", "allowance": 60}
                )
            },
            {},
        ),
        (
            "target_user_trimmed",
            {},
            {"daily_settings.json": dumps({"target_user": "  kid  ", "wake_time": "07:00"})},
        ),
        ("target_user_blank", {}, {"daily_settings.json": dumps({"target_user": "   "})}),
        ("target_user_not_a_string", {}, {"daily_settings.json": dumps({"target_user": 5})}),
    ]
    cases = []
    for name, profile, program_data in layouts:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_dir, pd_dir = root / "profile", root / "pd"
            profile_dir.mkdir()
            pd_dir.mkdir()
            for fname, text in profile.items():
                assert text is not None
                (profile_dir / fname).write_text(text, encoding="utf-8")
            for fname, text in program_data.items():
                assert text is not None
                (pd_dir / fname).write_text(text, encoding="utf-8")
            found = st.find_complete_daily_settings(
                profile_path=profile_dir / "daily_settings.json",
                program_data_path=pd_dir / "daily_settings.json",
            )
            cases.append(
                {
                    "name": name,
                    "profile": profile,
                    "program_data": program_data,
                    "found": None
                    if found is None
                    else {
                        "daily": daily_json(found[0]),
                        "source": "profile" if found[1].parent == profile_dir else "program_data",
                    },
                    "target_user": st.program_data_target_user(pd_dir),
                }
            )
    return cases


def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden agent-state vectors generated from kid_pc_monitor.agent_state by "
            "tests/state_vectors_gen.py. Do not edit by hand."
        ),
        "effective_allowance": effective_allowance_cases(),
        "rollover": rollover_cases(),
        "to_dict": to_dict_cases(),
        "load_daily": load_daily_cases(),
        "is_complete_daily": complete_daily_cases(),
        "load_runtime": load_runtime_cases(),
        "legacy_to_state": legacy_cases(),
        "store": store_cases(),
        "installer_helpers": installer_helper_cases(),
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
            print(f"{VECTORS_PATH} is out of date; run tests/state_vectors_gen.py", file=sys.stderr)
            return 1
        return 0
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

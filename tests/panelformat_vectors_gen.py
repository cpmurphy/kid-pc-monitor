"""Generate the golden web-panel formatting vectors shared by Python and Go.

A snapshot of the web panel's pure helpers for a fixed set of inputs, written
to ``testdata/panelformat/vectors.json``:

* :mod:`kid_pc_monitor.panel_format` (durations, dates, remaining minutes,
  snapshot timestamps),
* ``remote_client.settings_to_pc_info``, ``action_request_fields`` and
  ``format_agent_connection_error``,
* ``scan_store.dashboard_status_key``.

``go/panel/format`` must reproduce every case; ``tests/test_panelformat_vectors.py``
fails when the file is stale.

    python tests/panelformat_vectors_gen.py          # rewrite the vectors file
    python tests/panelformat_vectors_gen.py --check  # exit 1 if the file is stale

Numbers keep Python's int/float distinction in the JSON (``60`` vs ``60.0``) and
Go checks it, because the panel persists these dicts as JSON. Inputs are kept to
what every supported Python (3.11+) treats the same way.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kid_pc_monitor import panel_format as pf  # noqa: E402
from kid_pc_monitor import remote_client as rc  # noqa: E402
from kid_pc_monitor import scan_store  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "panelformat" / "vectors.json"


# ---------------------------------------------------------------------------
# panel_format
# ---------------------------------------------------------------------------
MINUTES_INPUTS: list[int | float | None] = [
    None,
    0,
    1,
    59,
    60,
    61,
    90,
    120.4,
    0.49,
    0.5,
    1.5,
    2.5,
    59.5,
    60.49,
    89.99999,
    1440,
    -5,
    -60,
    -61,
    -0.5,
    -1.5,
]

SECONDS_INPUTS: list[int | float] = [
    0,
    29,
    30,
    31,
    59,
    60,
    89,
    90,
    150,
    3599,
    3600,
    5400,
    7260.5,
    -30,
    -90,
    86400,
]

USAGE_DATE_INPUTS = [
    "2026-10-19",
    "2026-10-06",
    "2026-01-01",
    "2024-02-29",
    "2026-12-31",
    "20261019",
    "not-a-date",
    "",
    "2026-13-01",
    "2026-02-30",
    "2026-10-1",
    " 2026-10-19",
]

REMAINING_INPUTS: list[Any] = [
    None,
    True,
    False,
    0,
    45,
    45.5,
    -3,
    "90 minutes",
    "90 minute",
    "90 mins",
    "90 min",
    "90",
    " 90 ",
    "90minutes",
    "\t7 min ",
    "90 minutes\n",
    "-5 minutes",
    "1.5 minutes",
    "0 minutes",
    "007 minutes",
    "90 Minutes",
    "90 minutess",
    "90 m",
    "1e3",
    ".5",
    "5.",
    "+5",
    "- 5",
    "No limits set",
    "",
    "   ",
    "٣ minutes",
    " 12 min",
    [],
    {},
]

SNAPSHOT_NOWS = [
    "2026-06-05T18:00:00-05:00",
    "2026-01-01T00:30:00+01:00",
]

SNAPSHOT_RECORDED = [
    None,
    "",
    "2026-06-05T15:30:00-05:00",
    "2026-06-05T09:05:00-05:00",
    "2026-06-05T12:00:00-05:00",
    "2026-06-05T00:07:00-05:00",
    "2026-06-05T23:59:59-05:00",
    "2026-06-04T15:30:00-05:00",
    "2026-06-01T15:30:00-05:00",
    "2026-05-31T08:00:00-05:00",
    "2025-12-31T23:00:00+01:00",
    "2025-12-31T22:59:00Z",
    "2025-12-31T23:30:00Z",
    "2025-12-30T10:00:00+01:00",
    "2026-06-05T22:30:00+00:00",
    "2026-06-05T04:30:00+00:00",
    "2026-06-05T20:00:00+05:30",
    "2026-06-05T15:30:00",
    "2026-06-05T15:30:00.250000-05:00",
    "2026-06-05 15:30:00-05:00",
    "2026-06-05",
    "not-a-date",
    "2026-06-05T25:00:00",
]


def iso_now(text: str) -> datetime:
    return datetime.fromisoformat(text)


def minutes_cases() -> list[dict[str, Any]]:
    return [{"in": m, "out": pf.format_minutes_duration(m)} for m in MINUTES_INPUTS]


def seconds_cases() -> list[dict[str, Any]]:
    return [{"in": s, "out": pf.format_seconds_duration(s)} for s in SECONDS_INPUTS]


def usage_date_cases() -> list[dict[str, Any]]:
    return [{"in": d, "out": pf.format_usage_date(d)} for d in USAGE_DATE_INPUTS]


def remaining_cases() -> list[dict[str, Any]]:
    return [{"in": v, "out": pf.parse_remaining_minutes(v)} for v in REMAINING_INPUTS]


def snapshot_cases() -> list[dict[str, Any]]:
    return [
        {
            "recorded_at": rec,
            "now": now,
            "out": pf.format_snapshot_recorded_at(rec, now=iso_now(now)),
        }
        for now in SNAPSHOT_NOWS
        for rec in SNAPSHOT_RECORDED
    ]


# ---------------------------------------------------------------------------
# remote_client
# ---------------------------------------------------------------------------
FULL_SETTINGS: dict[str, Any] = {
    "name": "KID-PC",
    "status": "UNLOCKED",
    "current_user": "kid",
    "daily_limit": 120,
    "bed_time": "21:00",
    "wake_time": "07:00",
    "cumulative_extension": 900,
    "accumulated_seconds": 3725,
    "time_remaining": 73,
    "manual_lock": False,
    "enforcement_active": False,
    "enforcement_reason": None,
    "access_status": "Unlocked",
}

SETTINGS_CASES: list[tuple[dict[str, Any], str, str | None]] = [
    (FULL_SETTINGS, "192.168.1.20", None),
    ({}, "192.168.1.21", None),
    ({}, "192.168.1.21", "fallback-host"),
    ({"name": ""}, "10.0.0.2", "fallback-host"),
    ({"name": "", "status": ""}, "10.0.0.2", ""),
    ({"status": "LOCKED"}, "10.0.0.3", None),
    ({"status": "LOCKED", "manual_lock": True}, "10.0.0.3", None),
    ({"status": "UNLOCKED", "manual_lock": 1}, "10.0.0.3", None),
    ({"status": "UNLOCKED", "manual_lock": "yes"}, "10.0.0.3", None),
    ({"status": "UNLOCKED", "manual_lock": ""}, "10.0.0.3", None),
    ({"daily_limit": 60}, "10.0.0.4", None),
    ({"daily_limit": 0}, "10.0.0.4", None),
    ({"daily_limit": 0, "cumulative_extension": 0}, "10.0.0.4", None),
    ({"daily_limit": None, "cumulative_extension": 600}, "10.0.0.4", None),
    ({"daily_limit": 45, "cumulative_extension": 90}, "10.0.0.4", None),
    ({"daily_limit": 45.5, "cumulative_extension": 30}, "10.0.0.4", None),
    ({"cumulative_extension": -60}, "10.0.0.4", None),
    ({"cumulative_extension": 59.9, "accumulated_seconds": 12.7}, "10.0.0.4", None),
    ({"cumulative_extension": "120", "accumulated_seconds": " 30 "}, "10.0.0.4", None),
    ({"cumulative_extension": True, "accumulated_seconds": False}, "10.0.0.4", None),
    ({"accumulated_seconds": "1_000"}, "10.0.0.4", None),
    ({"time_remaining": 0}, "10.0.0.5", None),
    ({"time_remaining": -4}, "10.0.0.5", None),
    ({"time_remaining": 12.5}, "10.0.0.5", None),
    ({"time_remaining": 30.0}, "10.0.0.5", None),
    ({"time_remaining": "No limits set"}, "10.0.0.5", None),
    ({"time_remaining": True}, "10.0.0.5", None),
    ({"time_remaining": None}, "10.0.0.5", None),
    ({"bed_time": ""}, "10.0.0.6", None),
    ({"bed_time": "22:15", "wake_time": "06:30"}, "10.0.0.6", None),
    ({"enforcement_active": True, "enforcement_reason": "bedtime"}, "10.0.0.7", None),
    ({"enforcement_active": 0}, "10.0.0.7", None),
    ({"enforcement_active": "x"}, "10.0.0.7", None),
    ({"access_status": ""}, "10.0.0.8", None),
    ({"access_status": "Locked — bedtime", "status": "LOCKED"}, "10.0.0.8", None),
    ({"status": "UNKNOWN", "current_user": None}, "10.0.0.9", None),
    ({"extra_key": "ignored", "status": "UNLOCKED"}, "10.0.0.9", None),
    # Values a well-behaved agent never sends: Python raises.
    ({"cumulative_extension": "abc"}, "10.0.0.10", None),
    ({"accumulated_seconds": "1.5"}, "10.0.0.10", None),
    ({"accumulated_seconds": [1]}, "10.0.0.10", None),
    ({"daily_limit": "60"}, "10.0.0.10", None),
]


def settings_cases() -> list[dict[str, Any]]:
    out = []
    for settings, host, fallback in SETTINGS_CASES:
        case: dict[str, Any] = {"settings": settings, "host": host, "hostname_fallback": fallback}
        try:
            case["result"] = rc.settings_to_pc_info(
                dict(settings), host=host, hostname_fallback=fallback
            )
        except (TypeError, ValueError) as exc:
            case["error"] = type(exc).__name__
        out.append(case)
    return out


ACTION_CASES: list[tuple[str, dict[str, Any] | None]] = [
    ("lock", None),
    ("lock", {"minutes": "ignored"}),
    ("shutdown", {}),
    ("message", {"message": "Dinner is ready"}),
    ("message", {}),
    ("message", {"message": ""}),
    ("message", {"message": 42}),
    ("message", {"message": None}),
    ("extend_time", {"minutes": 30}),
    ("extend_time", {"minutes": "15"}),
    ("extend_time", {"minutes": " 15 "}),
    ("extend_time", {"minutes": "+15"}),
    ("extend_time", {"minutes": "-15"}),
    ("extend_time", {"minutes": "1_5"}),
    ("extend_time", {"minutes": 30.9}),
    ("extend_time", {"minutes": -2.5}),
    ("extend_time", {"minutes": True}),
    ("extend_time", {"minutes": "abc"}),
    ("extend_time", {"minutes": "1.5"}),
    ("extend_time", {"minutes": ""}),
    ("extend_time", {"minutes": "it's"}),
    ("extend_time", {"minutes": None}),
    ("extend_time", {"minutes": [5]}),
    ("extend_time", {"minutes": {"n": 5}}),
    ("extend_time", {}),
    ("extend_time", None),
    ("clear_manual_lock", None),
    ("clear_extensions", None),
    ("set_daily_limit", {"minutes": 90}),
    ("set_daily_limit", {"minutes": "90"}),
    ("set_daily_limit", {"minutes": ""}),
    ("set_daily_limit", {"minutes": None}),
    ("set_daily_limit", {}),
    ("set_daily_limit", {"minutes": 0}),
    ("set_daily_limit", {"minutes": "x"}),
    ("set_bed_time", {"time": "21:30"}),
    ("set_bed_time", {}),
    ("clear_bed_time", None),
    ("clear_lock_times", None),
    ("set_wake_time", {"time": "07:00"}),
    ("set_wake_time", {"time": ""}),
    ("clear_usage_limit", None),
    ("get_logs", None),
    ("get_logs", {"tail": 50}),
    ("get_logs", {"tail": "20"}),
    ("get_logs", {"tail": 0}),
    ("get_logs", {"tail": ""}),
    ("get_logs", {"tail": "many"}),
    ("unlock", None),
    ("", None),
    ("LOCK", None),
    ("bogus's", {}),
]


def action_cases() -> list[dict[str, Any]]:
    out = []
    for name, payload in ACTION_CASES:
        case: dict[str, Any] = {"action_name": name, "payload": payload}
        try:
            action, var, val, tail = rc.action_request_fields(name, payload)
            case["result"] = {"action": action, "var": var, "val": val, "tail": tail}
        except (ValueError, KeyError, TypeError) as exc:
            # The message PanelReverseServer.perform_action shows the parent.
            case["error"] = f"Invalid value for {name}: {exc}"
        out.append(case)
    return out


CONNECTION_ERRORS = [
    "",
    "   ",
    "timed out",
    "stale_timestamp: timestamp outside allowed window",
    "Timestamp outside allowed window (skew 75s)",
    "No shared secret is configured. Re-run the installer to set the panel/agent "
    "shared secret on this machine.",
    "authentication_failed: signature did not verify",
    "AUTHENTICATION_FAILED",
    "Signature did not verify",
    "Cannot reach agent at 10.0.0.5:9999: [Errno 111] Connection refused",
    "Cannot reach agent at 10.0.0.5:9999: timestamp outside allowed window",
    "cannot reach agent at 10.0.0.5: ",
    "Cannot reach agent at 10.0.0.5: Cannot reach agent at x: boom",
    "cannot reach agent at host",
    "Agent said: nope",
    "  padded message  ",
    "Ünïcode: ERROR",
]


def connection_error_cases() -> list[dict[str, Any]]:
    return [
        {"in": text, "out": rc.format_agent_connection_error(ConnectionError(text))}
        for text in CONNECTION_ERRORS
    ]


# ---------------------------------------------------------------------------
# scan_store
# ---------------------------------------------------------------------------
STATUS_KEY_CASES: list[dict[str, Any]] = [
    {},
    {"reachable": True},
    {"reachable": False},
    {"reachable": None},
    {"reachable": 0},
    {"reachable": "yes"},
    {"locked": True},
    {"locked": 1},
    {"locked": ""},
    {"reachable": False, "locked": True},
    {"agent_not_running": True},
    {"agent_not_running": True, "reachable": True},
    {"connection_error": "boom", "reachable": False},
    {"connection_error": "", "reachable": False},
    {"connection_error": "", "locked": True},
    {"connection_error": "boom", "locked": True, "reachable": True},
]


def status_key_cases() -> list[dict[str, Any]]:
    return [{"in": c, "out": scan_store.dashboard_status_key(c)} for c in STATUS_KEY_CASES]


# ---------------------------------------------------------------------------
# Python value semantics the Go port emulates (go/panel/pyval)
# ---------------------------------------------------------------------------
DATETIME_ISO_INPUTS = [
    "2026-06-05T15:30:00-05:00",
    "2026-06-05T15:30:00+05:30",
    "2026-06-05T15:30:00+00:00",
    "2026-06-05T15:30:00-00:00",
    "2026-06-05T15:30:00Z",
    "2026-06-05T15:30:00",
    "2026-06-05 15:30:00",
    "2026-06-05x15:30:00",
    "2026-06-05T15:30",
    "2026-06-05T15",
    "2026-06-05T1530",
    "2026-06-05T153000",
    "20260605T153000",
    "20260605T153000-0500",
    "2026-06-05T15:30:00.5",
    "2026-06-05T15:30:00,25",
    "2026-06-05T15:30:00.123456",
    "2026-06-05T15:30:00.1234567",
    "2026-06-05T15:30:00.123-05:00",
    "2026-06-05T15:30:00+05",
    "2026-06-05T15:30:00+0530",
    "2026-06-05T15:30:00+05:30:15",
    "2026-06-05T15:30:00-23:59",
    "2026-06-05",
    "20260605",
    "2026-W23",
    "2026-W23-5",
    "2026W235",
    "2026-W23-5T10:00",
    "2020-W53-7",
    "2026-02-28T23:59:59",
    "2024-02-29T00:00:00",
    "2026-02-29T00:00:00",
    "2026-13-01T00:00:00",
    "0000-01-01T00:00:00",
    "2026-06-05T",
    "2026-06-05T15:30:00.",
    "2026-06-05T15:3000",
    "2026-06-05T15:30:60",
    "2026-06-05T25:00",
    "2026-06-05T15:30:00Zx",
    "2026-06-05T15:30:00+24:00",
    "2026-06-05T15:30:00+",
    "2026-6-5T15:30",
    " 2026-06-05",
    "2026-06-05 ",
    "not-a-date",
    "",
    "2026-06",
]

DATE_ISO_INPUTS = [
    "2026-10-19",
    "20261019",
    "2026-W42-1",
    "2026-W42",
    "2026W421",
    "2026W42",
    "2024-02-29",
    "2026-02-29",
    "2026-00-10",
    "2026-10-19T00:00",
    "2026-1019",
    "2026-10-1",
    "",
    "abcdefgh",
]

INT_INPUTS: list[Any] = [
    None,
    True,
    False,
    0,
    -7,
    12.9,
    -12.9,
    1e15,
    "42",
    " 42\n",
    "+42",
    "-42",
    "1_000",
    "1__000",
    "_1",
    "1_",
    "\u0664\u0662",
    "4 2",
    "4.2",
    "",
    "-",
    "0x10",
    "it's",
    'say "hi"',
    "tab\tnewline\n",
    [],
    {},
]

FLOAT_REPR_INPUTS = [
    0.0,
    -0.0,
    1.0,
    30.0,
    0.1,
    1.5,
    -2.25,
    1e-4,
    1e-5,
    1.5e-7,
    123456789.125,
    1e15,
    1e16,
    1.2345e16,
    1e22,
    2.5e-300,
    1 / 3,
    100.0 / 60,
]

STR_REPR_INPUTS = [
    "",
    "abc",
    "it's",
    'say "hi"',
    "both ' and \"",
    "back\\slash",
    "tab\tcr\rnl\n",
    "bell\x07 del\x7f",
    "café ✓",
    "nbsp\u00a0zwsp\u200b",
    "\U0001f600",
]


JSON_DUMPS_INPUTS: list[Any] = [
    None,
    True,
    0,
    -12,
    60.0,
    1e-7,
    1e16,
    0.1,
    "plain",
    'quote " backslash \\ slash /',
    "ctl \b\f\n\r\t \x00 \x1f \x7f",
    "café ✓ \U0001f600",
    "<script>&</script>",
    [],
    [1, 2.5, "x", None, [True]],
    {},
    {"b": 1, "a": {"z": [], "y": 2.0}, "é": "ü"},
]


def int_case(value: Any) -> dict[str, Any]:
    try:
        return {"in": value, "result": int(value)}
    except (TypeError, ValueError) as exc:
        return {"in": value, "error": type(exc).__name__, "message": str(exc)}


def pyval_vectors() -> dict[str, Any]:
    def dt_out(text: str) -> str | None:
        try:
            return datetime.fromisoformat(text).isoformat()
        except ValueError:
            return None

    def d_out(text: str) -> str | None:
        try:
            return date.fromisoformat(text).isoformat()
        except ValueError:
            return None

    return {
        "datetime_fromisoformat": [{"in": s, "out": dt_out(s)} for s in DATETIME_ISO_INPUTS],
        "date_fromisoformat": [{"in": s, "out": d_out(s)} for s in DATE_ISO_INPUTS],
        "int": [int_case(v) for v in INT_INPUTS],
        "float_repr": [{"in": f, "out": repr(f)} for f in FLOAT_REPR_INPUTS],
        "str_repr": [{"in": s, "out": repr(s)} for s in STR_REPR_INPUTS],
        # Byte-exact json.dumps output; Go sorts dict keys, so these do too.
        "json_dumps": [{"in": v, "out": json.dumps(v, sort_keys=True)} for v in JSON_DUMPS_INPUTS],
    }


def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden web-panel formatting vectors generated from kid_pc_monitor.panel_format, "
            "remote_client and scan_store by tests/panelformat_vectors_gen.py. "
            "Do not edit by hand."
        ),
        "format_minutes_duration": minutes_cases(),
        "format_seconds_duration": seconds_cases(),
        "format_usage_date": usage_date_cases(),
        "parse_remaining_minutes": remaining_cases(),
        "format_snapshot_recorded_at": snapshot_cases(),
        "settings_to_pc_info": settings_cases(),
        "action_request_fields": action_cases(),
        "format_agent_connection_error": connection_error_cases(),
        "dashboard_status_key": status_key_cases(),
        "pyval": pyval_vectors(),
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
                f"{VECTORS_PATH} is out of date; run tests/panelformat_vectors_gen.py",
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

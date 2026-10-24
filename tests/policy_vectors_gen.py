"""Generate the golden lock-policy vectors shared by the Python and Go implementations.

A snapshot of :mod:`kid_pc_monitor.lock_policy` for a fixed set of inputs,
written to ``testdata/policy/vectors.json``.  ``go/policy`` must reproduce every
case; ``tests/test_policy_vectors.py`` fails when the file is stale.

    python tests/policy_vectors_gen.py          # rewrite the vectors file
    python tests/policy_vectors_gen.py --check  # exit 1 if the file is stale

Datetimes are naive wall-clock ISO strings, exactly as the agent uses them.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import sys
from datetime import datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kid_pc_monitor import lock_policy as lp  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "policy" / "vectors.json"


def hhmm(value: dtime | None) -> str | None:
    return None if value is None else f"{value.hour:02d}:{value.minute:02d}"


def t(text: str | None) -> dtime | None:
    return None if text is None else lp.parse_time_hhmm(text)


def tod(text: str) -> dtime:
    return lp.parse_time_hhmm(text)


# ---------------------------------------------------------------------------
# Simple helpers
# ---------------------------------------------------------------------------
USERS = ["kid", "parent", "Kid", ""]
USER_LISTS: list[list[str] | None] = [None, [], ["kid"], ["kid", "other"], ["parent"]]


def should_monitor_cases() -> list[dict[str, Any]]:
    cases = []
    for user, monitored, exempt in itertools.product(USERS, USER_LISTS, USER_LISTS):
        cases.append(
            {
                "user": user,
                "monitored": monitored,
                "exempt": exempt,
                "result": lp.should_monitor_user(user, monitored, exempt),
            }
        )
    return cases


PARSE_TIME_INPUTS = [
    "07:00",
    "7:00",
    "7:05",
    "00:00",
    "23:59",
    " 07:05 ",
    "\t21:30\n",
    "+7:05",
    "07 :05",
    "7: 5",
    "5_9:5_9",
    "24:00",
    "23:60",
    "-1:30",
    "07:-1",
    "7",
    "",
    " ",
    "07:05:00",
    "07-05",
    "a:b",
    "07:",
    ":30",
    "7.5:00",
    "0x7:00",
    "１２:３０",  # fullwidth digits: Python accepts, see go/policy/doc.go
]
# Unicode digits are a documented Go divergence; keep them out of the shared vectors.
PARSE_TIME_SHARED = [text for text in PARSE_TIME_INPUTS if text.isascii()]


def parse_time_cases() -> list[dict[str, Any]]:
    cases = []
    for text in PARSE_TIME_SHARED:
        case: dict[str, Any] = {"input": text}
        try:
            case["result"] = hhmm(lp.parse_time_hhmm(text))
        except ValueError:
            case["error"] = True
        cases.append(case)
    return cases


NOWS = [
    "2026-05-17T00:00:00",
    "2026-05-17T00:05:00",
    "2026-05-17T06:59:59.999999",
    "2026-05-17T07:00:00",
    "2026-05-17T07:00:30.250000",
    "2026-05-17T12:30:15",
    "2026-05-17T20:59:30.500000",
    "2026-05-17T21:00:00",
    "2026-05-17T21:05:00",
    "2026-05-17T23:59:59",
    "2026-05-18T00:00:00",
    "2026-03-01T06:30:00",  # day after a leap-year-free February boundary
    "2024-03-01T05:00:00",  # after Feb 29
    "2026-01-01T03:00:00",  # period date crosses a year boundary
    "2026-03-08T02:30:00",  # US DST gap: naive arithmetic must ignore it
    "2026-11-01T01:30:00",
]
WAKES = ["07:00", "00:00", "06:30", "23:59", "12:00"]
BEDS: list[str | None] = [None, "21:00", "00:00", "07:00", "06:00", "23:30", "06:30", "12:00"]


def usage_period_cases() -> list[dict[str, Any]]:
    return [
        {
            "now": now,
            "wake": wake,
            "result": lp.usage_period_date(datetime.fromisoformat(now), tod(wake)).isoformat(),
        }
        for now, wake in itertools.product(NOWS, WAKES)
    ]


def curfew_cases() -> list[dict[str, Any]]:
    return [
        {
            "now": now,
            "bed": bed,
            "wake": wake,
            "result": lp.is_in_bedtime_curfew(datetime.fromisoformat(now), tod(bed), tod(wake)),
        }
        for now, bed, wake in itertools.product(NOWS, [b for b in BEDS if b], WAKES)
    ]


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------
ALLOWANCES: list[float | None] = [None, 0, 1, 60, 90.5, 120, 120.25, 100.04, 0.05, 1e-05, 1440]
ACCUMULATED: list[float] = [0, 0.5, 59.9, 60, 90.5, 120, 120.3, 1e6]


def decision_case(
    now: str,
    bed: str | None,
    allowance: float | None,
    accumulated: float,
    monitor: bool,
    manual: bool,
    wake: str,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "now": datetime.fromisoformat(now),
        "bed_time": t(bed),
        "effective_usage_allowance_minutes": allowance,
        "accumulated_minutes": accumulated,
        "monitor_user": monitor,
        "wake_time": t(wake),
    }
    decision = lp.lock_decision(**kwargs, manual_lock_active=manual)
    enforcement_active, enforcement_reason = lp.enforcement_state(**kwargs)
    return {
        "in": {
            "now": now,
            "bed": bed,
            "allowance": allowance,
            "accumulated": accumulated,
            "monitor": monitor,
            "manual": manual,
            "wake": wake,
        },
        "should_lock": decision.should_lock,
        "reason": decision.reason,
        "minutes": lp.minutes_until_lock(**kwargs, manual_lock_active=manual),
        "enforcement_active": enforcement_active,
        "enforcement_reason": enforcement_reason,
    }


def decision_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    # Schedule grid: every time-of-day edge against every bed/wake pair.
    for now, bed, wake in itertools.product(NOWS, BEDS, WAKES):
        cases.append(decision_case(now, bed, None, 0, True, False, wake))
    # Allowance grid at a fixed clock, with and without a bedtime.
    for bed, allowance, accumulated in itertools.product([None, "21:00"], ALLOWANCES, ACCUMULATED):
        cases.append(
            decision_case("2026-05-17T12:30:15", bed, allowance, accumulated, True, False, "07:00")
        )
    # Flags.
    for monitor, manual, bed in itertools.product([True, False], [True, False], [None, "21:00"]):
        cases.append(decision_case("2026-05-17T22:00:00", bed, 60, 61, monitor, manual, "07:00"))
        cases.append(decision_case("2026-05-17T12:00:00", bed, 60, 5, monitor, manual, "07:00"))
    # Seeded random sample of the whole space.
    rng = random.Random(20260517)
    for _ in range(400):
        cases.append(
            decision_case(
                rng.choice(NOWS),
                rng.choice(BEDS),
                rng.choice(ALLOWANCES),
                rng.choice(ACCUMULATED),
                rng.random() < 0.85,
                rng.random() < 0.2,
                rng.choice(WAKES),
            )
        )
    return cases


BRIEF_REASONS = [
    "Before wake-up time 07:00",
    "Past bedtime 21:00",
    "Daily allowance of 120 minutes reached",
    "Manual lock requested",
    "BEFORE WAKE-UP",
    "PAST BEDTIME",
    "",
    "something else",
    "daily allowance 90.5",
]


def brief_reason_cases() -> list[dict[str, Any]]:
    return [{"reason": r, "result": lp.brief_enforcement_reason(r)} for r in BRIEF_REASONS]


def access_status_cases() -> list[dict[str, Any]]:
    cases = []
    for manual, active, reason, screen in itertools.product(
        [True, False], [True, False], [None, "", "past bedtime"], [True, False]
    ):
        cases.append(
            {
                "manual_lock": manual,
                "enforcement_active": active,
                "enforcement_reason": reason,
                "screen_locked": screen,
                "result": lp.format_access_status(
                    manual_lock=manual,
                    enforcement_active=active,
                    enforcement_reason=reason,
                    screen_locked=screen,
                ),
            }
        )
    return cases


def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden lock-policy vectors generated from kid_pc_monitor.lock_policy by "
            "tests/policy_vectors_gen.py. Do not edit by hand."
        ),
        "default_wake_time": hhmm(lp.DEFAULT_WAKE_TIME),
        "should_monitor_user": should_monitor_cases(),
        "parse_time_hhmm": parse_time_cases(),
        "usage_period_date": usage_period_cases(),
        "is_in_bedtime_curfew": curfew_cases(),
        "decisions": decision_cases(),
        "brief_enforcement_reason": brief_reason_cases(),
        "format_access_status": access_status_cases(),
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
                f"{VECTORS_PATH} is out of date; run tests/policy_vectors_gen.py", file=sys.stderr
            )
            return 1
        return 0
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

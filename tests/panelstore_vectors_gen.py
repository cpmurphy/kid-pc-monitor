"""Generate the golden web-panel store vectors shared by Python and Go.

Each scenario runs a list of store operations (the panel's ``panel.db``
writers: ``scan_store``, ``snapshot_store``, ``agent_sync_store``) against a
fresh database at fixed instants in a fixed timezone (``panel_clock.fixed``).
After every step it records what the panel's readers return and a dump of
every table, written to ``testdata/panelstore/vectors.json``.

``go/panel/store`` replays each scenario and must agree after every step, both
on the query results and on the rows it wrote, so a database written by
either panel reads the same in the other. ``tests/test_panelstore_vectors.py``
fails when the file is stale.

    python tests/panelstore_vectors_gen.py          # rewrite the vectors file
    python tests/panelstore_vectors_gen.py --check  # exit 1 if the file is stale

Payload columns are compared as parsed JSON (keeping int/float apart), not as
bytes. Datetimes are ``isoformat()`` strings. ``tz`` is a fixed offset
(``"-05:00"``) or an IANA zone name.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any
from unittest import mock
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kid_pc_monitor import agent_sync_store, panel_clock, panel_db  # noqa: E402
from kid_pc_monitor import scan_store as scans  # noqa: E402
from kid_pc_monitor import snapshot_store as snaps  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "panelstore" / "vectors.json"

A = "192.168.1.10"
B = "192.168.1.11"
C = "192.168.1.12"


def pc(**fields: Any) -> dict[str, Any]:
    """A panel PC-info payload as settings_to_pc_info builds it."""
    base: dict[str, Any] = {
        "hostname": "KID-PC",
        "status": "UNLOCKED",
        "locked": False,
        "current_user": "kid",
        "daily_limit": 120,
        "accumulated_seconds": 600,
        "cumulative_extension_seconds": 0,
        "effective_limit_minutes": 120.0,
        "time_remaining": "110 minutes",
        "access_status": "Unlocked",
        "reachable": True,
    }
    base.update(fields)
    return {k: v for k, v in base.items() if v is not DROP}


DROP = object()


def step(at: str, op: str, **args: Any) -> dict[str, Any]:
    return {"at": at, "op": op, "args": args}


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
SCENARIOS: list[dict[str, Any]] = [
    {
        "name": "registry_coalesce_and_status_changes",
        "tz": "-05:00",
        "queries": {"ips": [A], "hostnames": ["KID-PC", "kid-pc", "RENAMED"], "users": []},
        "steps": [
            step("2026-06-05T10:00:00-05:00", "record_poll_inspect", ip=A, pc_info=pc(ip=A)),
            step(
                "2026-06-05T10:00:05.750000-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(ip=A, accumulated_seconds=605),
            ),
            step(
                "2026-06-05T10:01:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(ip=A, status="LOCKED", locked=True, access_status="Screen locked"),
            ),
            step(
                "2026-06-05T10:02:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info={"hostname": "KID-PC", "ip": A, "reachable": False},
            ),
            step(
                "2026-06-05T10:03:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info={
                    "hostname": "KID-PC",
                    "ip": A,
                    "reachable": False,
                    "connection_error": "Authentication failed",
                },
            ),
            step(
                "2026-06-05T10:04:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(ip=A, hostname="RENAMED"),
            ),
            step(
                "2026-06-05T10:05:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(ip=A, hostname="", status="UNLOCKED"),
            ),
            step(
                "2026-06-05T10:06:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(ip=A),
                when="2026-06-05T09:00:00+00:00",
            ),
        ],
    },
    {
        "name": "prune_keeps_sole_pc_then_removes_stale",
        "tz": "-05:00",
        "queries": {"ips": [A, B], "hostnames": ["KID-PC", "OTHER"], "users": ["kid"]},
        "steps": [
            step("2026-06-05T08:00:00-05:00", "record_poll_inspect", ip=A, pc_info=pc(ip=A)),
            step("2026-06-05T19:59:00-05:00", "prune_stale_tracked_ips"),
            step("2026-06-05T20:01:00-05:00", "prune_stale_tracked_ips"),
            step("2026-06-05T20:02:00-05:00", "prune_stale_tracked_ips"),
            step(
                "2026-06-05T20:03:00-05:00",
                "record_poll_inspect",
                ip=B,
                pc_info=pc(ip=B, hostname="OTHER"),
            ),
            step("2026-06-05T20:04:00-05:00", "prune_stale_tracked_ips"),
            step("2026-06-05T20:05:00-05:00", "prune_stale_tracked_ips", max_age_hours=0.01),
        ],
    },
    {
        "name": "prune_contact_from_snapshots_and_failures",
        "tz": "+01:00",
        "queries": {"ips": [A, B, C], "hostnames": [], "users": ["kid"]},
        "steps": [
            step("2026-01-10T08:00:00+01:00", "record_poll_inspect", ip=A, pc_info=pc(ip=A)),
            step(
                "2026-01-10T08:00:00+01:00",
                "record_poll_inspect",
                ip=B,
                pc_info=pc(ip=B, hostname="B-PC"),
            ),
            step(
                "2026-01-10T08:00:00+01:00",
                "record_poll_inspect",
                ip=C,
                pc_info=pc(ip=C, hostname="C-PC"),
            ),
            # A keeps answering through a snapshot only; B only fails; C goes quiet.
            step("2026-01-10T19:00:00+01:00", "save_snapshot", pc_info=pc(ip=A)),
            step(
                "2026-01-10T19:30:00+01:00",
                "record_poll_inspect",
                ip=B,
                pc_info={"hostname": "B-PC", "ip": B, "reachable": False},
            ),
            step(
                "2026-01-10T19:40:00+01:00",
                "save_poll_snapshot",
                pc_info={"hostname": "B-PC", "ip": B, "reachable": False},
            ),
            step("2026-01-10T20:30:00+01:00", "prune_stale_tracked_ips"),
            step("2026-01-11T07:30:00+01:00", "prune_stale_tracked_ips"),
        ],
    },
    {
        "name": "snapshots_usage_history_and_trim",
        "tz": "-07:00",
        "queries": {
            "ips": [A, B],
            "hostnames": ["KID-PC", "LAPTOP"],
            "users": ["kid", "sib", "nobody"],
        },
        "steps": [
            step("2026-05-28T09:00:00-07:00", "save_snapshot", pc_info=pc(ip=A)),
            step("2026-05-29T21:00:00-07:00", "maybe_trim_old_rows"),
            step(
                "2026-06-01T09:00:00-07:00",
                "save_snapshot",
                pc_info=pc(ip=A, accumulated_seconds=1800, time_remaining="90 minutes"),
            ),
            step(
                "2026-06-01T17:30:00-07:00",
                "save_snapshot",
                pc_info=pc(
                    ip=A,
                    accumulated_seconds=5400,
                    cumulative_extension_seconds=900,
                    time_remaining="45 minutes",
                ),
            ),
            step(
                "2026-06-02T12:00:00-07:00",
                "save_snapshot",
                pc_info=pc(ip=B, hostname="LAPTOP", accumulated_seconds=60.5, daily_limit=None),
            ),
            step(
                "2026-06-02T12:05:00-07:00",
                "save_snapshot",
                pc_info=pc(ip=B, hostname="LAPTOP", current_user="sib", time_remaining=None),
            ),
            step("2026-06-03T08:00:00-07:00", "save_snapshot", pc_info=pc(ip=A, reachable=False)),
            step("2026-06-03T08:01:00-07:00", "save_snapshot", pc_info=pc(ip=A, current_user="")),
            step("2026-06-03T08:02:00-07:00", "save_snapshot", pc_info=pc(ip=A, hostname=None)),
            step(
                "2026-06-03T08:03:00-07:00",
                "save_snapshot",
                pc_info=pc(ip=DROP, accumulated_seconds=None, time_remaining="No limits set"),
            ),
            step(
                "2026-06-04T23:59:00-07:00",
                "save_poll_snapshot",
                pc_info=pc(ip=A, accumulated_seconds=7200),
            ),
            step(
                "2026-06-05T00:00:30-07:00",
                "save_poll_snapshot",
                pc_info=pc(ip=A, hostname=DROP, current_user=None),
            ),
            step("2026-06-05T00:01:00-07:00", "save_poll_snapshot", pc_info=pc(ip=DROP)),
            # Trim ran on 05-28 (via save_snapshot) so it is skipped until 06-04.
            step("2026-06-04T08:59:00-07:00", "maybe_trim_old_rows"),
            step("2026-06-05T09:00:00-07:00", "save_snapshot", pc_info=pc(ip=A)),
            step("2026-06-09T10:00:00-07:00", "maybe_trim_old_rows"),
            step("2026-06-12T10:00:00-07:00", "maybe_trim_old_rows"),
        ],
    },
    {
        "name": "dashboard_dedupe_and_snapshot_overlay",
        "tz": "-05:00",
        "queries": {
            "ips": [A, B, C],
            "hostnames": ["KID-PC", "kid-pc", "LAPTOP"],
            "users": ["kid"],
            "panel_lookups": [["KID-PC", A], ["KID-PC", B], [None, C], ["LAPTOP", None]],
        },
        "steps": [
            step("2026-06-05T10:00:00-05:00", "record_poll_inspect", ip=A, pc_info=pc(ip=A)),
            step("2026-06-05T10:00:00-05:00", "save_poll_snapshot", pc_info=pc(ip=A)),
            # The same PC after a DHCP change, with differently cased hostname.
            step(
                "2026-06-05T11:00:00-05:00",
                "record_poll_inspect",
                ip=B,
                pc_info=pc(ip=B, hostname="kid-pc", accumulated_seconds=900),
            ),
            step(
                "2026-06-05T11:00:00-05:00",
                "save_poll_snapshot",
                pc_info=pc(ip=B, hostname="kid-pc", accumulated_seconds=900),
            ),
            step(
                "2026-06-05T11:05:00-05:00",
                "record_poll_inspect",
                ip=C,
                pc_info={"hostname": f"PC at {C}", "ip": C, "reachable": False},
            ),
            step(
                "2026-06-05T11:10:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info={"hostname": "KID-PC", "ip": A, "reachable": False},
            ),
            step(
                "2026-06-05T11:20:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(ip=A, status="LOCKED", locked=True),
            ),
            step(
                "2026-06-05T11:20:00-05:00",
                "save_poll_snapshot",
                pc_info=pc(ip=A, status="LOCKED", locked=True),
            ),
            step(
                "2026-06-05T11:30:00-05:00",
                "record_poll_inspect",
                ip=C,
                pc_info=pc(ip=C, hostname="LAPTOP"),
            ),
            step(
                "2026-06-05T11:31:00-05:00",
                "record_poll_inspect",
                ip=B,
                pc_info={
                    "hostname": "kid-pc",
                    "ip": B,
                    "reachable": False,
                    "connection_error": "timed out",
                },
            ),
        ],
    },
    {
        # Equal contact times: the status rank, then the greater IP, picks the card.
        "name": "dashboard_dedupe_tie_breaks",
        "tz": "-05:00",
        "queries": {"ips": [A, B], "hostnames": ["TWIN"], "users": []},
        "steps": [
            step(
                "2026-06-05T10:00:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(ip=A, hostname="TWIN"),
            ),
            step(
                "2026-06-05T10:00:00-05:00",
                "record_poll_inspect",
                ip=B,
                pc_info=pc(ip=B, hostname="twin"),
            ),
            step(
                "2026-06-05T10:00:00-05:00",
                "record_poll_inspect",
                ip=B,
                pc_info={"hostname": "twin", "ip": B, "reachable": False},
            ),
            step(
                "2026-06-05T10:00:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info={"hostname": "TWIN", "ip": A, "connection_error": "boom"},
            ),
        ],
    },
    {
        "name": "panel_snapshot_fallbacks",
        "tz": "-05:00",
        "queries": {
            "ips": [A, B],
            "hostnames": ["KID-PC"],
            "users": ["kid"],
            "panel_lookups": [["KID-PC", A], ["KID-PC", B], [None, B], ["NOPE", B]],
        },
        "steps": [
            step("2026-06-05T09:00:00-05:00", "save_snapshot", pc_info=pc(ip=A)),
            step(
                "2026-06-05T09:30:00-05:00",
                "sql",
                sql=(
                    "INSERT OR REPLACE INTO snapshots (username, hostname, ip, snapshot_date,"
                    " recorded_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)"
                ),
                params=[
                    "",
                    "KID-PC",
                    A,
                    "2026-06-05",
                    "2026-06-05T09:30:00-05:00",
                    '{"hostname": "KID-PC", "ip": "192.168.1.10", "reachable": false}',
                ],
            ),
            step(
                "2026-06-05T10:00:00-05:00",
                "sql",
                sql=(
                    "INSERT OR REPLACE INTO snapshots (username, hostname, ip, snapshot_date,"
                    " recorded_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)"
                ),
                params=[
                    "other",
                    "KID-PC",
                    A,
                    "2026-06-05",
                    "2026-06-05T10:00:00-05:00",
                    '{"hostname": "KID-PC", "status": "UNLOCKED", "reachable": false}',
                ],
            ),
            step(
                "2026-06-05T11:00:00-05:00",
                "save_snapshot",
                pc_info=pc(ip=B, accumulated_seconds=1200),
            ),
        ],
    },
    {
        "name": "reverse_agent_heartbeats",
        "tz": "+05:30",
        "queries": {"ips": [A, B], "hostnames": ["KID-PC", "LAPTOP"], "users": []},
        "steps": [
            step(
                "2026-06-05T10:00:00.900000+05:30",
                "record_agent_poll",
                hostname="KID-PC",
                ip=A,
                pc_info=pc(ip=A, reachable=False),
            ),
            step("2026-06-05T10:02:59+05:30", "noop"),
            step("2026-06-05T10:03:01+05:30", "noop"),
            step(
                "2026-06-05T10:04:00+05:30",
                "record_agent_poll",
                hostname="LAPTOP",
                ip=A,
                pc_info=pc(ip=A, hostname="LAPTOP"),
            ),
            step(
                "2026-06-05T10:05:00+05:30",
                "record_agent_poll",
                hostname="KID-PC",
                ip=B,
                pc_info=pc(ip=B),
            ),
            step("2026-06-05T10:06:00+05:30", "clear_agent_for_ip", ip=A),
            step("2026-06-05T10:07:00+05:30", "clear_agent_for_hostname", hostname="KID-PC"),
        ],
    },
    {
        "name": "legacy_schema_and_naive_timestamps",
        "tz": "-05:00",
        "legacy_sql": [
            "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL,"
            " network_label TEXT NOT NULL, subnet TEXT NOT NULL, error TEXT)",
            "CREATE TABLE scan_pcs (scan_id INTEGER NOT NULL, ip TEXT NOT NULL,"
            " payload_json TEXT NOT NULL, PRIMARY KEY (scan_id, ip),"
            " FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE)",
            "INSERT INTO scans (scanned_at, network_label, subnet, error)"
            " VALUES ('2026-06-05T08:00:00', 'Home', '192.168.1.0/24', NULL)",
            "INSERT INTO scans (scanned_at, network_label, subnet, error)"
            " VALUES ('2026-06-05T08:30:00', 'Home', '192.168.1.0/24', 'scan failed')",
            "INSERT INTO scan_pcs (scan_id, ip, payload_json) VALUES"
            ' (1, \'192.168.1.10\', \'{"hostname": "OLD-PC", "status": "UNLOCKED",'
            ' "daily_limit": 60.0, "note": "caf\\u00e9"}\')',
            "INSERT INTO scan_pcs (scan_id, ip, payload_json) VALUES"
            ' (1, \'192.168.1.11\', \'{"status": "LOCKED", "locked": true}\')',
            "INSERT INTO scan_pcs (scan_id, ip, payload_json) VALUES"
            " (2, '192.168.1.12', '{\"hostname\": \"ERR-PC\"}')",
        ],
        "queries": {"ips": [A, B, C], "hostnames": ["OLD-PC", "old-pc", "ERR-PC"], "users": []},
        "steps": [
            step("2026-06-05T09:00:00-05:00", "noop"),
            step(
                "2026-06-05T09:05:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info={"hostname": "OLD-PC", "status": "UNLOCKED", "daily_limit": 60.0},
            ),
            step("2026-06-05T20:30:00-05:00", "prune_stale_tracked_ips"),
        ],
    },
    {
        "name": "dst_spring_forward_new_york",
        "tz": "America/New_York",
        "queries": {"ips": [A], "hostnames": ["KID-PC"], "users": ["kid"]},
        "steps": [
            step("2026-03-07T22:00:00-05:00", "save_snapshot", pc_info=pc(ip=A)),
            step("2026-03-07T22:00:00-05:00", "record_poll_inspect", ip=A, pc_info=pc(ip=A)),
            step(
                "2026-03-08T01:30:00-05:00",
                "save_snapshot",
                pc_info=pc(ip=A, accumulated_seconds=900),
            ),
            step(
                "2026-03-08T07:00:00Z",
                "save_snapshot",
                pc_info=pc(ip=A, accumulated_seconds=1200),
            ),
            step(
                "2026-03-08T12:00:00-04:00",
                "sql",
                sql=(
                    "INSERT OR REPLACE INTO snapshots (username, hostname, ip, snapshot_date,"
                    " recorded_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)"
                ),
                params=[
                    "kid",
                    "KID-PC",
                    A,
                    "2026-03-06",
                    "2026-03-06T23:00:00",
                    '{"hostname": "KID-PC", "status": "UNLOCKED", "reachable": true,'
                    ' "accumulated_seconds": 42}',
                ],
            ),
            step("2026-03-08T12:00:00-04:00", "prune_stale_tracked_ips"),
            step("2026-03-14T09:00:00-04:00", "save_snapshot", pc_info=pc(ip=A)),
            step("2026-03-15T09:00:00-04:00", "maybe_trim_old_rows"),
        ],
    },
    {
        "name": "payload_value_kinds",
        "tz": "-05:00",
        "queries": {"ips": [A], "hostnames": ["ÇAFÉ-PC"], "users": ["kïd"]},
        "steps": [
            step(
                "2026-06-05T10:00:00-05:00",
                "record_poll_inspect",
                ip=A,
                pc_info=pc(
                    ip=A,
                    hostname="ÇAFÉ-PC",
                    current_user="kïd",
                    daily_limit=60.0,
                    effective_limit_minutes=75.5,
                    accumulated_seconds=0,
                    lock_times=["21:00"],
                    enforcement_reason=None,
                    nested={"a": [1, 2.0, "3", None, True], "b": {}},
                    big=12345678901234,
                    small=1e-7,
                    quote='say "hi" \\ \n\t',
                    emoji="\U0001f600",
                ),
            ),
            step(
                "2026-06-05T10:00:00-05:00",
                "save_snapshot",
                pc_info=pc(
                    ip=A,
                    hostname="ÇAFÉ-PC",
                    current_user="kïd",
                    daily_limit=60.0,
                    accumulated_seconds=61.0,
                    cumulative_extension_seconds="30",
                    time_remaining=12.5,
                ),
            ),
        ],
    },
]


# ---------------------------------------------------------------------------
# Running a scenario against the Python stores
# ---------------------------------------------------------------------------
def make_tz(spec: str) -> tzinfo:
    if spec[0] in "+-":
        sign = -1 if spec[0] == "-" else 1
        hours, minutes = spec[1:].split(":")
        return timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))
    return ZoneInfo(spec)


def iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def snapshot_out(result: tuple[str, dict[str, Any]] | None) -> Any:
    return None if result is None else [result[0], result[1]]


def dump_tables(db_path: Path) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    try:

        def rows(sql: str, payload_index: int | None = None) -> list[list[Any]]:
            out = []
            for row in conn.execute(sql).fetchall():
                values = list(row)
                if payload_index is not None:
                    values[payload_index] = json.loads(values[payload_index])
                out.append(values)
            return out

        return {
            "snapshots": rows(
                "SELECT username, hostname, ip, snapshot_date, recorded_at, payload_json"
                " FROM snapshots ORDER BY username, hostname, snapshot_date",
                5,
            ),
            "scans": rows(
                "SELECT id, scanned_at, network_label, subnet, error FROM scans ORDER BY id"
            ),
            "scan_pcs": rows(
                "SELECT scan_id, ip, hostname, payload_json FROM scan_pcs ORDER BY scan_id, ip",
                3,
            ),
            "panel_meta": rows("SELECT key, value FROM panel_meta ORDER BY key"),
            "reverse_agents": rows(
                "SELECT hostname, ip, last_seen, payload_json FROM reverse_agents"
                " ORDER BY hostname",
                3,
            ),
        }
    finally:
        conn.close()


def query_state(queries: dict[str, Any], db_path: Path) -> dict[str, Any]:
    pcs, last_poll_at = snaps.get_dashboard_pcs()
    state: dict[str, Any] = {
        "tracked": [[ip, payload] for ip, payload in scans.get_tracked_ips().items()],
        "dashboard": {
            "pcs": [[ip, info] for ip, info in pcs.items()],
            "last_poll_at": iso(last_poll_at),
        },
        "contact_times": [
            [ip, iso(seen)] for ip, seen in sorted(scans.get_tracked_ip_contact_times().items())
        ],
        "by_ip": {},
        "by_hostname": {},
        "by_user": {},
        "panel_lookups": [],
        "tables": dump_tables(db_path),
    }
    for ip in queries.get("ips", []):
        state["by_ip"][ip] = {
            "scan_pc": scans.get_scan_pc(ip),
            "poll_updated_at": iso(scans.get_pc_poll_updated_at(ip)),
            "latest_snapshot": snapshot_out(snaps.get_latest_snapshot_for_pc(ip=ip)),
            "latest_reachable_snapshot": snapshot_out(
                snaps.get_latest_snapshot_for_pc(ip=ip, reachable_only=True)
            ),
            "latest_panel_snapshot": snapshot_out(snaps.get_latest_panel_snapshot_for_pc(ip=ip)),
            "recent_agent": agent_sync_store.recent_agent_for_ip(ip),
        }
    for hostname in queries.get("hostnames", []):
        state["by_hostname"][hostname] = {
            "scan_pc": scans.get_scan_pc_by_hostname(hostname),
            "latest_snapshot": snapshot_out(snaps.get_latest_snapshot_for_pc(hostname=hostname)),
            "recent_agent": agent_sync_store.recent_agent_for_hostname(hostname),
        }
    for user in queries.get("users", []):
        state["by_user"][user] = {
            "usage_7": snaps.get_usage_history_for_user(user, days=7),
            "usage_2": snaps.get_usage_history_for_user(user, days=2),
        }
    for hostname, ip in queries.get("panel_lookups", []):
        state["panel_lookups"].append(
            [
                hostname,
                ip,
                snapshot_out(snaps.get_latest_panel_snapshot_for_pc(hostname=hostname, ip=ip)),
            ]
        )
    return state


def run_op(op: str, args: dict[str, Any], db_path: Path) -> Any:
    ops: dict[str, Callable[[], Any]] = {
        "noop": lambda: None,
        "record_poll_inspect": lambda: scans.record_poll_inspect(
            args["ip"],
            dict(args["pc_info"]),
            when=datetime.fromisoformat(args["when"]) if "when" in args else None,
        ),
        "save_snapshot": lambda: snaps.save_snapshot(dict(args["pc_info"])),
        "save_poll_snapshot": lambda: snaps.save_poll_snapshot(dict(args["pc_info"])),
        "maybe_trim_old_rows": lambda: snaps.maybe_trim_old_rows(),
        "record_agent_poll": lambda: agent_sync_store.record_agent_poll(
            args["hostname"], args["ip"], dict(args["pc_info"])
        ),
        "clear_agent_for_ip": lambda: agent_sync_store.clear_agent_for_ip(args["ip"]),
        "clear_agent_for_hostname": lambda: agent_sync_store.clear_agent_for_hostname(
            args["hostname"]
        ),
        "prune_stale_tracked_ips": lambda: sorted(
            scans.prune_stale_tracked_ips(max_age_hours=args.get("max_age_hours"))
        ),
    }
    if op == "sql":
        with panel_db.connect() as conn:
            conn.execute(args["sql"], args["params"])
            conn.commit()
        return None
    return ops[op]()


def run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    tz = make_tz(scenario["tz"])
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / panel_db.DB_FILENAME
        if scenario.get("legacy_sql"):
            conn = sqlite3.connect(db_path)
            for statement in scenario["legacy_sql"]:
                conn.execute(statement)
            conn.commit()
            conn.close()
        out_steps = []
        with mock.patch.object(panel_db, "_db_path_override", db_path):
            for item in scenario["steps"]:
                at = datetime.fromisoformat(item["at"])
                with panel_clock.fixed(lambda at=at: at, tz=tz):
                    result = run_op(item["op"], item["args"], db_path)
                    state = query_state(scenario["queries"], db_path)
                out_steps.append({**item, "result": result, "state": state})
        panel_db._initialized_paths.discard(db_path)
    return {
        "name": scenario["name"],
        "tz": scenario["tz"],
        "legacy_sql": scenario.get("legacy_sql", []),
        "queries": scenario["queries"],
        "steps": out_steps,
    }


def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden web-panel store vectors generated from kid_pc_monitor.scan_store, "
            "snapshot_store and agent_sync_store by tests/panelstore_vectors_gen.py. "
            "Do not edit by hand."
        ),
        "constants": {
            "stale_tracked_hours": scans.STALE_TRACKED_HOURS,
            "retention_days": snaps.RETENTION_DAYS,
            "trim_interval_days": snaps.TRIM_INTERVAL_DAYS,
            "recent_agent_seconds": agent_sync_store.RECENT_AGENT_SECONDS,
        },
        "scenarios": [run_scenario(s) for s in SCENARIOS],
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
                f"{VECTORS_PATH} is out of date; run tests/panelstore_vectors_gen.py",
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

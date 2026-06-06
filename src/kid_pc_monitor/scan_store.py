"""SQLite persistence for web panel network scan results."""

from __future__ import annotations

import json
import sqlite3
from datetime import date, datetime, timedelta
from typing import Any

from kid_pc_monitor.panel_db import connect

STALE_TRACKED_HOURS = 12


def _json_default(value: Any) -> str:
    """Serialize values json.dumps cannot handle natively (e.g. scan timestamps)."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def save_scan(
    *,
    pcs: dict[str, dict[str, Any]],
    scanned_at: datetime,
    network_label: str,
    subnet: str,
    error: str | None = None,
) -> None:
    """Record the result of a network scan (accumulates PCs across scans)."""
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (scanned_at, network_label, subnet, error)
            VALUES (?, ?, ?, ?)
            """,
            (
                scanned_at.isoformat(timespec="seconds"),
                network_label,
                subnet,
                error,
            ),
        )
        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        if pcs:
            conn.executemany(
                """
                INSERT INTO scan_pcs (scan_id, ip, payload_json)
                VALUES (?, ?, ?)
                """,
                [
                    (scan_id, ip, json.dumps({**info, "ip": ip}, default=_json_default))
                    for ip, info in pcs.items()
                ],
            )
        conn.commit()


def save_scan_error(error: str, *, subnet: str = "") -> None:
    """Record a scan error without clearing previously tracked PCs."""
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (scanned_at, network_label, subnet, error)
            VALUES (?, ?, ?, ?)
            """,
            (
                datetime.now().astimezone().isoformat(timespec="seconds"),
                "",
                subnet,
                error,
            ),
        )
        conn.commit()


def _latest_scan_row(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, scanned_at, network_label, subnet, error FROM scans ORDER BY id DESC LIMIT 1"
    ).fetchone()


def load_scan_metadata() -> dict[str, Any]:
    with connect() as conn:
        row = _latest_scan_row(conn)

    if not row:
        return {
            "last_scan": None,
            "last_scan_network": None,
            "scan_subnet": "",
            "scan_error": None,
        }

    last_scan = datetime.fromisoformat(row["scanned_at"])
    return {
        "last_scan": last_scan,
        "last_scan_network": row["network_label"] or None,
        "scan_subnet": row["subnet"] or "",
        "scan_error": row["error"],
    }


def get_tracked_ips() -> dict[str, dict[str, Any]]:
    """Return all tracked PCs from successful scans (latest sighting per IP)."""
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT sp.ip, sp.payload_json, sp.scan_id
            FROM scan_pcs sp
            INNER JOIN scans s ON sp.scan_id = s.id
            WHERE s.error IS NULL
            ORDER BY sp.ip, sp.scan_id DESC
            """
        ).fetchall()

    tracked: dict[str, dict[str, Any]] = {}
    for row in rows:
        ip = row["ip"]
        if ip in tracked:
            continue
        tracked[ip] = json.loads(row["payload_json"])
    return tracked


def get_discovered_pcs() -> dict[str, dict[str, Any]]:
    """Return all tracked PCs from successful scans."""
    return get_tracked_ips()


def get_scan_pc(ip: str) -> dict[str, Any] | None:
    """Return PC info for an IP from tracked scan results."""
    return get_tracked_ips().get(ip)


def _parse_db_datetime(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def _latest_reachable_snapshot_time(conn: sqlite3.Connection, ip: str) -> datetime | None:
    rows = conn.execute(
        """
        SELECT recorded_at, payload_json
        FROM snapshots
        WHERE ip = ?
        ORDER BY recorded_at DESC
        """,
        (ip,),
    ).fetchall()
    for row in rows:
        payload = json.loads(row["payload_json"])
        if payload.get("reachable"):
            return _parse_db_datetime(row["recorded_at"])
    return None


def _latest_scan_time(conn: sqlite3.Connection, ip: str) -> datetime | None:
    row = conn.execute(
        """
        SELECT s.scanned_at
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE sp.ip = ? AND s.error IS NULL
        ORDER BY s.id DESC
        LIMIT 1
        """,
        (ip,),
    ).fetchone()
    if not row:
        return None
    return _parse_db_datetime(row["scanned_at"])


def tracked_ip_last_updated(conn: sqlite3.Connection, ip: str) -> datetime | None:
    """Return when a tracked IP was last scanned or last known reachable."""
    candidates = [
        ts
        for ts in (_latest_scan_time(conn, ip), _latest_reachable_snapshot_time(conn, ip))
        if ts is not None
    ]
    if not candidates:
        return None
    return max(candidates)


def _stale_tracked_hours() -> float:
    return float(STALE_TRACKED_HOURS)


def prune_stale_tracked_ips(*, max_age_hours: float | None = None) -> list[str]:
    """Remove tracked PCs with no scan or reachable update within max_age_hours."""
    max_age = timedelta(
        hours=max_age_hours if max_age_hours is not None else _stale_tracked_hours()
    )
    cutoff = datetime.now().astimezone() - max_age
    pruned: list[str] = []

    with connect() as conn:
        ips = [
            row["ip"]
            for row in conn.execute(
                """
                SELECT DISTINCT sp.ip
                FROM scan_pcs sp
                INNER JOIN scans s ON sp.scan_id = s.id
                WHERE s.error IS NULL
                """
            ).fetchall()
        ]
        for ip in ips:
            last_updated = tracked_ip_last_updated(conn, ip)
            if last_updated is None or last_updated < cutoff:
                conn.execute("DELETE FROM scan_pcs WHERE ip = ?", (ip,))
                pruned.append(ip)
        conn.commit()

    return pruned

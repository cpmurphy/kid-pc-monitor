"""SQLite persistence for web panel network scan results."""

from __future__ import annotations

import json
import sqlite3
from datetime import date, datetime
from typing import Any

from kid_pc_monitor.panel_db import connect


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

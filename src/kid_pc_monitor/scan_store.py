"""SQLite persistence for web panel network scan results."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from kid_pc_monitor.panel_db import connect


def save_scan(
    *,
    pcs: dict[str, dict[str, Any]],
    scanned_at: datetime,
    network_label: str,
    subnet: str,
    error: str | None = None,
) -> None:
    """Record the result of a network scan (replaces the previous scan)."""
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
                [(scan_id, ip, json.dumps({**info, "ip": ip})) for ip, info in pcs.items()],
            )
        conn.execute("DELETE FROM scans WHERE id != ?", (scan_id,))
        conn.commit()


def save_scan_error(error: str, *, subnet: str = "") -> None:
    save_scan(
        pcs={},
        scanned_at=datetime.now().astimezone(),
        network_label="",
        subnet=subnet,
        error=error,
    )


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


def get_discovered_pcs() -> dict[str, dict[str, Any]]:
    """Return PC info from the most recent scan."""
    with connect() as conn:
        scan = _latest_scan_row(conn)
        if not scan or scan["error"]:
            return {}
        rows = conn.execute(
            "SELECT ip, payload_json FROM scan_pcs WHERE scan_id = ? ORDER BY ip",
            (scan["id"],),
        ).fetchall()

    return {row["ip"]: json.loads(row["payload_json"]) for row in rows}


def get_scan_pc(ip: str) -> dict[str, Any] | None:
    """Return PC info for an IP from the most recent successful scan."""
    return get_discovered_pcs().get(ip)

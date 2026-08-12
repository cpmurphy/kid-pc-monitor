"""SQLite persistence for web panel tracked PCs (reverse-connected agents)."""

from __future__ import annotations

import json
import sqlite3
from datetime import date, datetime, timedelta
from typing import Any

from kid_pc_monitor.panel_db import connect

STALE_TRACKED_HOURS = 12
POLL_NETWORK_LABEL = "poll"


def dashboard_status_key(pc_info: dict[str, Any]) -> str:
    """Badge-level status for coalescing poll updates (not full payload equality)."""
    if pc_info.get("connection_error"):
        return "cant_control"
    if pc_info.get("agent_not_running"):
        return "not_signed_in"
    if not pc_info.get("reachable", True):
        return "offline"
    if pc_info.get("locked"):
        return "locked"
    return "online"


def _json_default(value: Any) -> str:
    """Serialize values json.dumps cannot handle natively (e.g. timestamps)."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _payload_hostname(payload: dict[str, Any]) -> str | None:
    hostname = payload.get("hostname")
    return hostname if isinstance(hostname, str) and hostname else None


def _latest_scan_pc_for_ip(conn: sqlite3.Connection, ip: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT sp.scan_id, sp.payload_json
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE sp.ip = ? AND s.error IS NULL
        ORDER BY sp.scan_id DESC
        LIMIT 1
        """,
        (ip,),
    ).fetchone()


def _payload_from_row(row: sqlite3.Row) -> dict[str, Any]:
    payload = json.loads(row["payload_json"])
    payload["ip"] = row["ip"]
    return payload


def record_poll_inspect(ip: str, pc_info: dict[str, Any], *, when: datetime | None = None) -> None:
    """Update tracked registry from a reverse status update (coalesce by dashboard status)."""
    now = when or datetime.now().astimezone()
    payload = {**pc_info, "ip": ip}
    payload_json = json.dumps(payload, default=_json_default)
    hostname = _payload_hostname(payload)
    status = dashboard_status_key(payload)

    with connect() as conn:
        latest = _latest_scan_pc_for_ip(conn, ip)
        if latest is not None:
            existing = json.loads(latest["payload_json"])
            if dashboard_status_key(existing) == status:
                conn.execute(
                    """
                    UPDATE scan_pcs SET hostname = ?, payload_json = ?
                    WHERE scan_id = ? AND ip = ?
                    """,
                    (hostname, payload_json, latest["scan_id"], ip),
                )
                conn.execute(
                    "UPDATE scans SET scanned_at = ? WHERE id = ?",
                    (now.isoformat(timespec="seconds"), latest["scan_id"]),
                )
                conn.commit()
                return

        conn.execute(
            """
            INSERT INTO scans (scanned_at, network_label, subnet, error)
            VALUES (?, ?, ?, ?)
            """,
            (
                now.isoformat(timespec="seconds"),
                POLL_NETWORK_LABEL,
                "",
                None,
            ),
        )
        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO scan_pcs (scan_id, ip, hostname, payload_json) VALUES (?, ?, ?, ?)",
            (scan_id, ip, hostname, payload_json),
        )
        conn.commit()


def _prune_orphan_scans(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM scans
        WHERE id NOT IN (SELECT DISTINCT scan_id FROM scan_pcs)
        """
    )


def get_tracked_ips() -> dict[str, dict[str, Any]]:
    """Return all tracked PCs (latest sighting per IP)."""
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
    """Return all tracked PCs."""
    return get_tracked_ips()


def get_scan_pc(ip: str) -> dict[str, Any] | None:
    """Return PC info for an IP from the tracked registry."""
    return get_tracked_ips().get(ip)


def get_pc_poll_updated_at(ip: str) -> datetime | None:
    """Return when a tracked PC was last updated."""
    with connect() as conn:
        return _latest_scan_time(conn, ip)


def get_scan_pc_by_hostname(hostname: str) -> dict[str, Any] | None:
    """Return latest tracked PC info for a hostname."""
    with connect() as conn:
        row = conn.execute(
            """
            SELECT sp.ip, sp.payload_json, sp.scan_id
            FROM scan_pcs sp
            INNER JOIN scans s ON sp.scan_id = s.id
            WHERE sp.hostname COLLATE NOCASE = ? AND s.error IS NULL
            ORDER BY sp.scan_id DESC, sp.ip
            LIMIT 1
            """,
            (hostname,),
        ).fetchone()
    return _payload_from_row(row) if row else None


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


def _latest_reachable_scan_time(conn: sqlite3.Connection, ip: str) -> datetime | None:
    """Latest registry row where the IP was marked reachable."""
    rows = conn.execute(
        """
        SELECT s.scanned_at AS scanned_at, sp.payload_json AS payload_json
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE sp.ip = ? AND s.error IS NULL
        ORDER BY s.id DESC
        """,
        (ip,),
    ).fetchall()
    for row in rows:
        payload = json.loads(row["payload_json"])
        if payload.get("reachable", True):
            return _parse_db_datetime(row["scanned_at"])
    return None


def tracked_ip_last_updated(conn: sqlite3.Connection, ip: str) -> datetime | None:
    """Return when a tracked IP was last seen reachable."""
    candidates = [
        ts
        for ts in (_latest_reachable_scan_time(conn, ip), _latest_reachable_snapshot_time(conn, ip))
        if ts is not None
    ]
    if not candidates:
        return None
    return max(candidates)


def get_tracked_ip_contact_times() -> dict[str, datetime]:
    """Return the last time each tracked IP actually answered."""
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
        times = {ip: tracked_ip_last_updated(conn, ip) for ip in ips}
    return {ip: seen for ip, seen in times.items() if seen is not None}


def _stale_tracked_hours() -> float:
    return float(STALE_TRACKED_HOURS)


def prune_stale_tracked_ips(*, max_age_hours: float | None = None) -> list[str]:
    """Remove tracked PCs with no reachable update within max_age_hours."""
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
        _prune_orphan_scans(conn)
        conn.commit()

    return pruned

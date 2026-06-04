"""SQLite persistence for web panel inspect snapshots."""

from __future__ import annotations

import json
import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from kid_pc_monitor.paths import config_dir

DB_FILENAME = "panel_snapshots.db"
META_LAST_TRIM_AT = "last_trim_at"
RETENTION_DAYS = 7
TRIM_INTERVAL_DAYS = 7

_db_path_override: Path | None = None


def db_path() -> Path:
    if _db_path_override is not None:
        return _db_path_override
    return config_dir() / DB_FILENAME


def _local_today() -> date:
    return datetime.now().astimezone().date()


def _snapshot_date_str(when: datetime | None = None) -> str:
    dt = when or datetime.now().astimezone()
    return dt.date().isoformat()


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS snapshots (
            username TEXT NOT NULL,
            hostname TEXT NOT NULL,
            ip TEXT NOT NULL,
            snapshot_date TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY (username, hostname, snapshot_date)
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_hostname ON snapshots(hostname);
        CREATE INDEX IF NOT EXISTS idx_snapshots_username ON snapshots(username);

        CREATE TABLE IF NOT EXISTS panel_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )


def _get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM panel_meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO panel_meta (key, value) VALUES (?, ?)",
        (key, value),
    )


def save_snapshot(pc_info: dict[str, Any]) -> None:
    """Persist a successful inspect result (latest per user+PC per calendar day)."""
    if not pc_info.get("reachable"):
        return
    username = pc_info.get("current_user")
    hostname = pc_info.get("hostname")
    if not username or not hostname:
        return

    ip = pc_info.get("ip") or ""
    now = datetime.now().astimezone()
    snapshot_date = _snapshot_date_str(now)
    recorded_at = now.isoformat(timespec="seconds")
    payload_json = json.dumps(pc_info)

    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO snapshots
                (username, hostname, ip, snapshot_date, recorded_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, hostname, ip, snapshot_date, recorded_at, payload_json),
        )
        conn.commit()
        maybe_trim_old_rows(conn=conn)


def get_latest_snapshot_for_pc(
    *,
    hostname: str | None = None,
    ip: str | None = None,
) -> tuple[str, dict[str, Any]] | None:
    """Return the most recent snapshot for a PC (any logged-in user)."""
    if hostname:
        result = _query_latest_snapshot("hostname = ?", hostname)
        if result is not None:
            return result
    if ip:
        return _query_latest_snapshot("ip = ?", ip)
    return None


def _query_latest_snapshot(clause: str, param: str) -> tuple[str, dict[str, Any]] | None:
    with _connect() as conn:
        row = conn.execute(
            f"""
            SELECT recorded_at, payload_json
            FROM snapshots
            WHERE {clause}
            ORDER BY recorded_at DESC
            LIMIT 1
            """,
            (param,),
        ).fetchone()

    if not row:
        return None
    return row["recorded_at"], json.loads(row["payload_json"])


def _day_entry_from_payload(snapshot_date: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "date": snapshot_date,
        "accumulated_seconds": int(payload.get("accumulated_seconds") or 0),
        "daily_limit": payload.get("daily_limit"),
        "cumulative_extension_seconds": int(payload.get("cumulative_extension_seconds") or 0),
        "time_remaining": payload.get("time_remaining"),
        "recorded_at": payload.get("_recorded_at"),
    }


def _empty_day_entry(day: date) -> dict[str, Any]:
    return {"date": day.isoformat(), "no_data": True}


def get_usage_history_for_user(username: str, *, days: int = 7) -> list[dict[str, Any]]:
    """Return usage rows for the last N calendar days, grouped by hostname."""
    today = _local_today()
    start = today - timedelta(days=days - 1)
    start_str = start.isoformat()
    end_str = today.isoformat()

    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT hostname, snapshot_date, recorded_at, payload_json
            FROM snapshots
            WHERE username = ? AND snapshot_date >= ? AND snapshot_date <= ?
            ORDER BY hostname, snapshot_date
            """,
            (username, start_str, end_str),
        ).fetchall()

    by_hostname: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        payload = json.loads(row["payload_json"])
        payload["_recorded_at"] = row["recorded_at"]
        host = row["hostname"]
        by_hostname.setdefault(host, {})[row["snapshot_date"]] = _day_entry_from_payload(
            row["snapshot_date"], payload
        )

    day_range = [start + timedelta(days=offset) for offset in range(days)]
    groups: list[dict[str, Any]] = []
    for hostname in sorted(by_hostname):
        known = by_hostname[hostname]
        group_days: list[dict[str, Any]] = []
        for day in day_range:
            key = day.isoformat()
            group_days.append(known.get(key, _empty_day_entry(day)))
        groups.append({"hostname": hostname, "days": group_days})

    return groups


def maybe_trim_old_rows(*, conn: sqlite3.Connection | None = None) -> None:
    """Delete snapshots older than RETENTION_DAYS; run at most every TRIM_INTERVAL_DAYS."""
    now = datetime.now().astimezone()
    own_conn = conn is None
    if own_conn:
        conn = _connect()

    assert conn is not None
    last_trim_raw = _get_meta(conn, META_LAST_TRIM_AT)
    if last_trim_raw:
        last_trim = datetime.fromisoformat(last_trim_raw)
        if last_trim.tzinfo is None:
            last_trim = last_trim.astimezone()
        if now - last_trim < timedelta(days=TRIM_INTERVAL_DAYS):
            if own_conn:
                conn.close()
            return

    cutoff = (_local_today() - timedelta(days=RETENTION_DAYS)).isoformat()
    conn.execute("DELETE FROM snapshots WHERE snapshot_date < ?", (cutoff,))
    _set_meta(conn, META_LAST_TRIM_AT, now.isoformat(timespec="seconds"))
    conn.commit()
    if own_conn:
        conn.close()

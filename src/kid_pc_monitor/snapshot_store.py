"""SQLite persistence for web panel inspect snapshots."""

from __future__ import annotations

import json
import sqlite3
from datetime import date, datetime, timedelta
from typing import Any

from kid_pc_monitor.panel_db import connect, get_meta, set_meta
from kid_pc_monitor.scan_store import get_tracked_ips

META_LAST_TRIM_AT = "last_trim_at"
RETENTION_DAYS = 7
TRIM_INTERVAL_DAYS = 7


def _local_today() -> date:
    return datetime.now().astimezone().date()


def _snapshot_date_str(when: datetime | None = None) -> str:
    dt = when or datetime.now().astimezone()
    return dt.date().isoformat()


def _snapshot_username(pc_info: dict[str, Any]) -> str:
    user = pc_info.get("current_user")
    return user if isinstance(user, str) and user else ""


def save_snapshot(pc_info: dict[str, Any]) -> None:
    """Persist a successful inspect result (latest per user+PC per calendar day)."""
    if not pc_info.get("reachable"):
        return
    username = _snapshot_username(pc_info)
    hostname = pc_info.get("hostname")
    if not username or not hostname:
        return

    ip = pc_info.get("ip") or ""
    now = datetime.now().astimezone()
    snapshot_date = _snapshot_date_str(now)
    recorded_at = now.isoformat(timespec="seconds")
    payload_json = json.dumps(pc_info)

    with connect() as conn:
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


def save_poll_snapshot(pc_info: dict[str, Any]) -> None:
    """Persist a successful poll result for dashboard display.

    Unreachable poll failures are tracked in the scan registry only so we do
    not overwrite the last reachable per-day snapshot used on the control page.
    """
    if not pc_info.get("reachable", True):
        return
    ip = pc_info.get("ip")
    if not ip:
        return
    hostname = pc_info.get("hostname") or f"PC at {ip}"
    username = _snapshot_username(pc_info)
    now = datetime.now().astimezone()
    snapshot_date = _snapshot_date_str(now)
    recorded_at = now.isoformat(timespec="seconds")
    payload = {**pc_info, "ip": ip, "hostname": hostname}
    payload_json = json.dumps(payload)

    with connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO snapshots
                (username, hostname, ip, snapshot_date, recorded_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, hostname, ip, snapshot_date, recorded_at, payload_json),
        )
        conn.commit()


def get_dashboard_pcs() -> tuple[dict[str, dict[str, Any]], datetime | None]:
    """Return tracked PCs with latest snapshot overlay for dashboard display."""
    tracked = get_tracked_ips()
    dashboard: dict[str, dict[str, Any]] = {}
    last_poll_at: datetime | None = None

    for ip, entry in tracked.items():
        if not entry.get("reachable", True) or entry.get("connection_error"):
            dashboard[ip] = {**entry, "ip": ip}
            continue

        snapshot = get_latest_snapshot_for_pc(ip=ip)
        if snapshot:
            recorded_at, payload = snapshot
            info = {**payload, "ip": ip, "snapshot_recorded_at": recorded_at}
            poll_time = datetime.fromisoformat(recorded_at)
            if poll_time.tzinfo is None:
                poll_time = poll_time.astimezone()
            if last_poll_at is None or poll_time > last_poll_at:
                last_poll_at = poll_time
        else:
            info = {**entry, "ip": ip}
        dashboard[ip] = info

    return dashboard, last_poll_at


def snapshot_has_panel_data(payload: dict[str, Any]) -> bool:
    """True when a snapshot row carries a full inspect result, not a bare failure."""
    return payload.get("status") is not None


def get_latest_snapshot_for_pc(
    *,
    hostname: str | None = None,
    ip: str | None = None,
    reachable_only: bool = False,
) -> tuple[str, dict[str, Any]] | None:
    """Return the most recent snapshot for a PC (any logged-in user)."""
    if hostname:
        result = _query_latest_snapshot("hostname = ?", hostname, reachable_only=reachable_only)
        if result is not None:
            return result
    if ip:
        return _query_latest_snapshot("ip = ?", ip, reachable_only=reachable_only)
    return None


def get_latest_panel_snapshot_for_pc(
    *,
    hostname: str | None = None,
    ip: str | None = None,
) -> tuple[str, dict[str, Any]] | None:
    """Return the best snapshot for the control-page stale-data fallback."""
    snapshot = get_latest_snapshot_for_pc(hostname=hostname, ip=ip, reachable_only=False)
    if snapshot is not None and snapshot_has_panel_data(snapshot[1]):
        return snapshot
    return get_latest_snapshot_for_pc(hostname=hostname, ip=ip, reachable_only=True)


def _query_latest_snapshot(
    clause: str, param: str, *, reachable_only: bool = False
) -> tuple[str, dict[str, Any]] | None:
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT recorded_at, payload_json
            FROM snapshots
            WHERE {clause}
            ORDER BY recorded_at DESC
            """,
            (param,),
        ).fetchall()

    for row in rows:
        payload = json.loads(row["payload_json"])
        if reachable_only and not payload.get("reachable"):
            continue
        return row["recorded_at"], payload
    return None


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

    with connect() as conn:
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
        conn = connect()

    assert conn is not None
    last_trim_raw = get_meta(conn, META_LAST_TRIM_AT)
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
    set_meta(conn, META_LAST_TRIM_AT, now.isoformat(timespec="seconds"))
    conn.commit()
    if own_conn:
        conn.close()

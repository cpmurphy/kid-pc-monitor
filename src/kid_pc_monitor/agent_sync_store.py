"""Panel-side persistence for reverse agent heartbeats."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from kid_pc_monitor.panel_db import connect

RECENT_AGENT_SECONDS = 180


def _now() -> datetime:
    return datetime.now().astimezone().replace(microsecond=0)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def record_agent_poll(hostname: str, ip: str, pc_info: dict[str, Any]) -> None:
    """Record the latest status reported by a reverse-connected agent."""
    now = _now().isoformat(timespec="seconds")
    payload = {**pc_info, "hostname": hostname, "ip": ip, "reachable": True}
    with connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO reverse_agents
                (hostname, ip, last_seen, payload_json)
            VALUES (?, ?, ?, ?)
            """,
            (hostname, ip, now, json.dumps(payload, default=_json_default)),
        )
        conn.commit()


def clear_agent_for_ip(ip: str) -> None:
    """Drop reverse-agent heartbeat rows so the IP is no longer treated as recent."""
    with connect() as conn:
        conn.execute("DELETE FROM reverse_agents WHERE ip = ?", (ip,))
        conn.commit()


def clear_agent_for_hostname(hostname: str) -> None:
    """Drop reverse-agent heartbeat rows for a hostname."""
    with connect() as conn:
        conn.execute("DELETE FROM reverse_agents WHERE hostname = ?", (hostname,))
        conn.commit()


def recent_agent_for_ip(
    ip: str,
    *,
    max_age_seconds: int = RECENT_AGENT_SECONDS,
) -> dict[str, Any] | None:
    """Return a recently connected reverse agent by IP, or None if stale/missing."""
    cutoff = _now() - timedelta(seconds=max_age_seconds)
    with connect() as conn:
        row = conn.execute(
            """
            SELECT hostname, ip, last_seen, payload_json
            FROM reverse_agents
            WHERE ip = ?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()
    if row is None:
        return None
    last_seen = _parse_dt(row["last_seen"])
    if last_seen is None or last_seen < cutoff:
        return None
    payload = json.loads(row["payload_json"])
    payload["hostname"] = row["hostname"]
    payload["ip"] = row["ip"]
    payload["last_seen"] = row["last_seen"]
    return payload


def recent_agent_for_hostname(
    hostname: str,
    *,
    max_age_seconds: int = RECENT_AGENT_SECONDS,
) -> dict[str, Any] | None:
    cutoff = _now() - timedelta(seconds=max_age_seconds)
    with connect() as conn:
        row = conn.execute(
            """
            SELECT hostname, ip, last_seen, payload_json
            FROM reverse_agents
            WHERE hostname = ?
            """,
            (hostname,),
        ).fetchone()
    if row is None:
        return None
    last_seen = _parse_dt(row["last_seen"])
    if last_seen is None or last_seen < cutoff:
        return None
    payload = json.loads(row["payload_json"])
    payload["hostname"] = row["hostname"]
    payload["ip"] = row["ip"]
    payload["last_seen"] = row["last_seen"]
    return payload

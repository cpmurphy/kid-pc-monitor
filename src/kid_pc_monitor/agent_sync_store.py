"""Panel-side persistence for reverse agent polling and queued commands."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta
from typing import Any

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.panel_db import connect

RECENT_AGENT_SECONDS = 180
COMMAND_TIMEOUT_SECONDS = 120

STATUS_PENDING = "pending"
STATUS_DELIVERED = "delivered"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


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
    """Record the latest status reported by a reverse-polling agent."""
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


def recent_agent_for_ip(
    ip: str,
    *,
    max_age_seconds: int = RECENT_AGENT_SECONDS,
) -> dict[str, Any] | None:
    """Return a recently polling agent by IP, or None if it is stale/missing."""
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


def enqueue_command(
    *,
    hostname: str,
    action_name: str,
    request_fields: dict[str, Any] | None = None,
    request_frame: str | None = None,
) -> int:
    """Store an unsigned command for later delivery.

    ``request_frame`` is accepted for old callers/tests and legacy rows, but
    normal reverse commands should use ``request_fields`` so the v3 timestamp is
    generated when the agent actually polls.
    """
    now = _now().isoformat(timespec="seconds")
    request_json = json.dumps(request_fields) if request_fields is not None else None
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO agent_commands
                (hostname, action_name, status, created_at, request_frame, request_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (hostname, action_name, STATUS_PENDING, now, request_frame or "", request_json),
        )
        command_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.commit()
    return command_id


def _build_delivery_frame(row: Any, *, secret: str, hostname: str) -> str:
    request_json = row["request_json"]
    if request_json:
        fields = json.loads(request_json)
        return proto.build_request(
            str(fields["action"]),
            secret=secret,
            var=fields.get("var"),
            val=fields.get("val"),
            tail=fields.get("tail"),
            name=hostname,
            req_id=secrets.token_hex(3),
        )
    return str(row["request_frame"])


def take_pending_commands(
    hostname: str,
    *,
    secret: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Return pending commands for an agent and mark them delivered."""
    now = _now().isoformat(timespec="seconds")
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, request_frame, request_json
            FROM agent_commands
            WHERE hostname = ? AND status = ?
            ORDER BY id
            LIMIT ?
            """,
            (hostname, STATUS_PENDING, limit),
        ).fetchall()
        commands: list[dict[str, Any]] = []
        delivered: list[tuple[str, int]] = []
        for row in rows:
            if row["request_json"] and secret is None:
                continue
            frame = _build_delivery_frame(row, secret=secret or "", hostname=hostname)
            command_id = int(row["id"])
            commands.append({"id": command_id, "request": frame})
            delivered.append((frame, command_id))
        if delivered:
            conn.executemany(
                """
                UPDATE agent_commands
                SET status = ?, delivered_at = ?, request_frame = ?
                WHERE id = ? AND hostname = ?
                """,
                [
                    (STATUS_DELIVERED, now, frame, command_id, hostname)
                    for frame, command_id in delivered
                ],
            )
        conn.commit()
    return commands


def record_command_result(
    command_id: int,
    response_frame: str,
    *,
    hostname: str,
    response: proto.Response | None = None,
    error_text: str | None = None,
) -> bool:
    status = STATUS_COMPLETED if response is not None and response.ok else STATUS_FAILED
    if response is not None:
        result_text = response.text
        error_text = None if response.ok else response.text
    else:
        result_text = None
    now = _now().isoformat(timespec="seconds")
    with connect() as conn:
        cursor = conn.execute(
            """
            UPDATE agent_commands
            SET status = ?,
                completed_at = ?,
                response_frame = ?,
                result_text = ?,
                error_text = ?
            WHERE id = ? AND hostname = ?
            """,
            (status, now, response_frame, result_text, error_text, command_id, hostname),
        )
        conn.commit()
    return cursor.rowcount == 1


def command_status(command_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, hostname, action_name, status, created_at, delivered_at,
                   completed_at, result_text, error_text
            FROM agent_commands
            WHERE id = ?
            """,
            (command_id,),
        ).fetchone()
    if row is None:
        return None

    status = row["status"]
    error = row["error_text"]
    delivered_at = _parse_dt(row["delivered_at"])
    response = row["result_text"]
    if status == STATUS_PENDING:
        response = "Command is waiting for the agent to poll."
    elif status == STATUS_DELIVERED:
        response = "Command delivered; waiting for result."
        if delivered_at is not None and _now() - delivered_at > timedelta(
            seconds=COMMAND_TIMEOUT_SECONDS
        ):
            status = STATUS_FAILED
            error = "The agent did not report a result before the command timed out."
    elif response is None:
        response = "Command completed"

    return {
        "id": int(row["id"]),
        "hostname": row["hostname"],
        "action_name": row["action_name"],
        "status": status,
        "success": status == STATUS_COMPLETED,
        "pending": status in (STATUS_PENDING, STATUS_DELIVERED),
        "response": error or response,
        "created_at": row["created_at"],
        "delivered_at": row["delivered_at"],
        "completed_at": row["completed_at"],
    }


def latest_completed_command(
    *,
    hostname: str,
    action_name: str,
) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, response_frame, result_text, error_text, completed_at
            FROM agent_commands
            WHERE hostname = ? AND action_name = ? AND status IN (?, ?)
            ORDER BY id DESC
            LIMIT 1
            """,
            (hostname, action_name, STATUS_COMPLETED, STATUS_FAILED),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "response_frame": row["response_frame"],
        "result_text": row["result_text"],
        "error_text": row["error_text"],
        "completed_at": row["completed_at"],
    }

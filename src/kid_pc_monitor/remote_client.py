"""Shared helpers for agent protocol exchange (panel reverse path and formatting)."""

from __future__ import annotations

import errno
import secrets
import socket
import sys
import threading
from typing import Any

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor import shared_secret

SharedSecretMissing = shared_secret.SharedSecretMissing

# Optional friendly names keyed by IP (used when presenting PCs in the panel).
CUSTOM_PC_NAMES: dict[str, str] = {
    # Example: '192.168.1.105': "Tommy's Laptop",
}

_verbose_lock = threading.Lock()


def _print_frame(prefix: str, frame: str, out: Any = sys.stdout) -> None:
    """Print a length-prefixed frame line-by-line with a curl-style prefix."""
    length = len(frame.encode("utf-8"))
    with _verbose_lock:
        print(f"{prefix} {length}", file=out)
        for line in frame.splitlines():
            print(f"{prefix} {line}", file=out)


def _legacy_access_status(status: str, manual_lock: bool) -> str:
    """Fallback access label for agents that do not expose access_status."""
    if manual_lock:
        return "Locked — manual lock"
    if status == "LOCKED":
        return "Screen locked"
    return "Unlocked"


def _discover_name(
    client: socket.socket, secret: str, *, verbose: bool = False, out: Any = sys.stdout
) -> str:
    """Run the unnamed ``get name`` handshake and return the agent's hostname."""
    body = proto.build_request("get", secret=secret, var="name", req_id=secrets.token_hex(3))
    if verbose:
        _print_frame(">", body, out=out)
    client.sendall(proto.encode_frame(body))
    response_body = proto.read_frame(client)
    if verbose:
        _print_frame("<", response_body, out=out)
    resp = proto.parse_response(response_body, secret=secret)
    if not resp.ok or not resp.name:
        raise proto.ProtocolError(
            proto.AUTHENTICATION_FAILED, "could not discover the agent's name"
        )
    return str(resp.name)


class AgentLogsUnavailable(ConnectionError):
    """The agent does not support log retrieval (unknown action)."""


def exchange_on_socket(
    sock: socket.socket,
    action: str,
    *,
    secret: str,
    var: str | None = None,
    val: Any = None,
    name: str | None = None,
    version: int = proto.CLIENT_DEFAULT_VERSION,
    tail: int | None = None,
    verbose: bool = False,
    out: Any = sys.stdout,
) -> proto.Response:
    """Send one signed request on an existing socket and return the response."""
    if name is None and action in proto.WRITE_ACTIONS:
        name = _discover_name(sock, secret, verbose=verbose, out=out)
    body = proto.build_request(
        action,
        secret=secret,
        var=var,
        val=val,
        req_id=secrets.token_hex(3),
        name=name,
        version=version,
        tail=tail,
    )
    if verbose:
        _print_frame(">", body, out=out)
    sock.sendall(proto.encode_frame(body))
    response_body = proto.read_frame(sock)
    if verbose:
        _print_frame("<", response_body, out=out)
    return proto.parse_response(
        response_body, secret=secret, expected_name=name, expected_version=version
    )


def format_agent_connection_error(exc: BaseException) -> str:
    """Turn low-level agent/client errors into parent-friendly text."""
    text = str(exc).strip()
    lower = text.lower()

    if "timestamp outside allowed window" in lower or "stale_timestamp" in lower:
        return (
            "This PC's clock is out of sync (common after sleep or pausing a VM). "
            "Correct the date and time on that computer, then try again."
        )

    if "no shared secret is configured" in lower:
        return (
            "No shared secret is configured on this computer. "
            "Re-run the installer on the kid PC and web panel host."
        )

    if "authentication_failed" in lower or "signature did not verify" in lower:
        return (
            "Authentication failed — the shared secret on this panel may not match "
            "the kid PC. Re-run the installers with the same secret."
        )

    marker = ": "
    idx = text.rfind(marker)
    if idx != -1 and "cannot reach agent at" in lower:
        detail = text[idx + len(marker) :].strip()
        if detail and detail.lower() != lower:
            return format_agent_connection_error(ConnectionError(detail))

    return text or "Could not communicate with the agent."


def is_offline_connection_error(exc: BaseException) -> bool:
    """True when the host is unreachable at the network layer (e.g. powered off)."""
    offline_errnos: set[int] = {113}  # Linux EHOSTUNREACH
    for name in ("EHOSTUNREACH", "EHOSTDOWN", "ENETUNREACH"):
        val = getattr(errno, name, None)
        if isinstance(val, int):
            offline_errnos.add(val)

    for err in (exc, exc.__cause__):
        if isinstance(err, OSError) and err.errno in offline_errnos:
            return True

    lower = str(exc).lower()
    return "no route to host" in lower or "[errno 113]" in lower


def is_agent_not_running_error(exc: BaseException) -> bool:
    """True when the host answered but nothing is listening on the agent port."""
    refused_errnos: set[int] = {111, 10061}  # Linux ECONNREFUSED, Windows WSAECONNREFUSED
    val = getattr(errno, "ECONNREFUSED", None)
    if isinstance(val, int):
        refused_errnos.add(val)

    for err in (exc, exc.__cause__):
        if isinstance(err, OSError) and err.errno in refused_errnos:
            return True

    lower = str(exc).lower()
    return "connection refused" in lower or "[errno 111]" in lower or "[winerror 10061]" in lower


def connection_failure_fields(exc: BaseException) -> dict[str, Any]:
    """Session/template fields when inspect or control actions cannot reach an agent."""
    if is_offline_connection_error(exc):
        return {"reachable": False}
    if is_agent_not_running_error(exc):
        return {"reachable": False, "agent_not_running": True}
    return {
        "reachable": False,
        "connection_error": format_agent_connection_error(exc),
    }


def action_request_fields(
    action_name: str,
    payload: dict[str, Any] | None = None,
) -> tuple[str, str | None, Any, int | None]:
    """Map a panel action name to protocol request fields."""
    p = payload or {}
    if action_name == "lock":
        return "lock", None, None, None
    if action_name == "shutdown":
        return "shutdown", None, None, None
    if action_name == "message":
        return "message", None, p.get("message", ""), None
    if action_name == "extend_time":
        return "extend", None, int(p["minutes"]), None
    if action_name == "clear_manual_lock":
        return "clear", "manual_lock", None, None
    if action_name == "clear_extensions":
        return "clear", "cumulative_extension", None, None
    if action_name == "set_daily_limit":
        minutes = p.get("minutes")
        if minutes is None or minutes == "":
            return "clear", "daily_limit", None, None
        return "set", "daily_limit", int(minutes), None
    if action_name == "set_bed_time":
        return "set", "bed_time", p.get("time"), None
    if action_name in ("clear_bed_time", "clear_lock_times"):
        return "clear", "bed_time", None, None
    if action_name == "set_wake_time":
        return "set", "wake_time", p.get("time"), None
    if action_name == "clear_usage_limit":
        return "clear", "daily_limit", None, None
    if action_name == "get_logs":
        return "get_logs", None, None, int(p.get("tail") or proto.DEFAULT_LOG_TAIL_LINES)
    raise KeyError(action_name)


def settings_to_pc_info(
    settings: dict[str, Any],
    *,
    host: str,
    hostname_fallback: str | None = None,
) -> dict[str, Any]:
    """Convert an agent settings payload into the panel PC-info shape."""
    status = settings.get("status") or "UNKNOWN"
    daily_limit = settings.get("daily_limit")
    bed_time = settings.get("bed_time")
    wake_time = settings.get("wake_time")
    extension_seconds = int(settings.get("cumulative_extension") or 0)
    accumulated_seconds = int(settings.get("accumulated_seconds") or 0)

    remaining_min = settings.get("time_remaining")
    time_remaining = f"{remaining_min} minutes" if remaining_min is not None else None

    lock_times: list[str] | None = [bed_time] if bed_time else None

    effective_limit: float | None
    if daily_limit is None and extension_seconds <= 0:
        effective_limit = None
    else:
        effective_limit = (daily_limit or 0) + extension_seconds / 60

    hostname = settings.get("name") or hostname_fallback or f"PC at {host}"

    manual_lock_active = bool(settings.get("manual_lock"))
    enforcement_active = settings.get("enforcement_active")
    if enforcement_active is None:
        enforcement_active = False
    else:
        enforcement_active = bool(enforcement_active)
    enforcement_reason = settings.get("enforcement_reason")
    access_status = settings.get("access_status")
    if access_status is None:
        access_status = _legacy_access_status(status, manual_lock_active)

    return {
        "ip": host,
        "hostname": hostname,
        "status": status,
        "locked": status == "LOCKED",
        "current_user": settings.get("current_user"),
        "daily_limit": daily_limit,
        "usage_limit": daily_limit,
        "bed_time": bed_time,
        "lock_times": lock_times,
        "wake_time": wake_time,
        "manual_lock_active": manual_lock_active,
        "enforcement_active": enforcement_active,
        "enforcement_reason": enforcement_reason,
        "access_status": access_status,
        "cumulative_extension_seconds": extension_seconds,
        "accumulated_seconds": accumulated_seconds,
        "effective_limit_minutes": effective_limit,
        "time_remaining": time_remaining,
        "reachable": True,
    }

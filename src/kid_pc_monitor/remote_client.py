"""TCP client for kid PC agents (pc_control.py remote server on port 9999)."""

from __future__ import annotations

import ipaddress
import secrets
import socket
import threading
from datetime import datetime
from typing import Any

from kid_pc_monitor import agent_protocol as proto

DEFAULT_PORT = 9999
CONNECT_TIMEOUT = 5
SCAN_CONNECT_TIMEOUT = 0.5
QUERY_TIMEOUT = 2

# Optional friendly names (same format as web_panel.py)
CUSTOM_PC_NAMES: dict[str, str] = {
    # Example: '192.168.1.105': "Tommy's Laptop",
}


from kid_pc_monitor.network import get_local_ip


def format_minutes_duration(minutes: int | float | None) -> str:
    """Format a minute count as H:MM or 'Not set'."""
    if minutes is None:
        return "Not set"
    total = int(round(minutes))
    hours, mins = divmod(total, 60)
    if hours:
        return f"{hours}:{mins:02d}"
    return f"{mins} min"


def format_seconds_duration(seconds: int | float) -> str:
    return format_minutes_duration(seconds / 60)


def get_default_scan_network() -> ipaddress.IPv4Network:
    local_ip = get_local_ip()
    return ipaddress.ip_network(f"{local_ip}/24", strict=False)


def parse_scan_subnet(subnet_arg: str | None) -> tuple[ipaddress.IPv4Network, str]:
    """
    Parse a user-supplied subnet into an ip_network.

    Accepts CIDR (192.168.123.0/24), three octets (192.168.123),
    or a host IP on a /24 (192.168.123.50). Empty means default LAN.
    """
    if subnet_arg is None or not str(subnet_arg).strip():
        network = get_default_scan_network()
        return network, str(network)

    raw = str(subnet_arg).strip()
    normalized = raw

    if "/" not in normalized:
        parts = normalized.split(".")
        if len(parts) == 3:
            normalized = f"{normalized}.0/24"
        elif len(parts) == 4:
            normalized = f"{'.'.join(parts[:3])}.0/24"
        else:
            raise ValueError(
                f"Invalid network '{raw}'. Use CIDR (192.168.123.0/24), "
                "three octets (192.168.123), or a host IP (192.168.123.50)."
            )

    try:
        network = ipaddress.ip_network(normalized, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid network '{raw}': {exc}") from exc

    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported.")

    return network, str(network)


def send_command(host: str, command: str, port: int = DEFAULT_PORT) -> tuple[bool, str]:
    """Send a raw protocol command and return (success, response text)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(CONNECT_TIMEOUT)
            client.connect((host, port))
            client.send(command.encode())
            response = client.recv(4096)
        return True, response.decode(errors="replace").strip()
    except OSError as exc:
        return False, str(exc)


def query_command(host: str, command: str, port: int = DEFAULT_PORT) -> str | None:
    """Run a read-only command; return response text or None on failure."""
    ok, response = send_command(host, command, port=port)
    return response if ok else None


# ---------------------------------------------------------------------------
# Structured protocol (version 1) client helpers
# ---------------------------------------------------------------------------
def send_request(
    host: str,
    action: str,
    *,
    var: str | None = None,
    val: Any = None,
    port: int = DEFAULT_PORT,
    timeout: float = CONNECT_TIMEOUT,
) -> proto.Response:
    """Send one length-framed structured request and return the parsed response.

    Raises OSError on connection problems and ProtocolError on a malformed
    response frame.
    """
    body = proto.build_request(action, var=var, val=val, req_id=secrets.token_hex(3))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect((host, port))
        client.sendall(proto.encode_frame(body))
        response_body = proto.read_frame(client)
    return proto.parse_response(response_body)


def request_text(
    host: str,
    action: str,
    *,
    var: str | None = None,
    val: Any = None,
    port: int = DEFAULT_PORT,
) -> tuple[bool, str]:
    """Send a structured request; return (success, human-readable text)."""
    try:
        resp = send_request(host, action, var=var, val=val, port=port)
    except (OSError, proto.ProtocolError) as exc:
        return False, str(exc)
    return resp.ok, resp.text


def get_settings(host: str, port: int = DEFAULT_PORT) -> dict[str, Any] | None:
    """Fetch every variable in a single round-trip, or None if unreachable."""
    try:
        resp = send_request(host, "get", var="settings", port=port)
    except (OSError, proto.ProtocolError):
        return None
    return resp.settings if resp.ok else None


# Web-panel action names not yet expressible in the v1 protocol, mapped to the
# legacy line commands. Kept temporarily until the protocol grows these verbs.
def _legacy_panel_command(action_name: str, payload: dict[str, Any]) -> str | None:
    if action_name == "shutdown":
        return "SHUTDOWN"
    if action_name == "message":
        return f"MESSAGE:{payload.get('message', '')}"
    if action_name == "extend_time":
        return f"EXTEND_TIME:{int(payload['minutes'])}"
    if action_name == "clear_all":
        return "CLEAR_ALL"
    return None


def perform_action(
    host: str,
    action_name: str,
    payload: dict[str, Any] | None = None,
    port: int = DEFAULT_PORT,
) -> tuple[bool, str]:
    """Run a web-panel action over the structured protocol where possible.

    Falls back to the legacy line protocol for actions the v1 protocol does not
    yet cover (message, shutdown, extend_time, clear_all).
    """
    p = payload or {}
    try:
        if action_name == "lock":
            return request_text(host, "lock", port=port)
        if action_name == "clear_manual_lock":
            return request_text(host, "clear", var="manual_lock", port=port)
        if action_name == "clear_extensions":
            return request_text(host, "clear", var="cumulative_extension", port=port)
        if action_name == "set_daily_limit":
            minutes = p.get("minutes")
            if minutes is None or minutes == "":
                return request_text(host, "clear", var="daily_limit", port=port)
            return request_text(host, "set", var="daily_limit", val=int(minutes), port=port)
        if action_name == "set_bed_time":
            return request_text(host, "set", var="bed_time", val=p.get("time"), port=port)
        if action_name in ("clear_bed_time", "clear_lock_times"):
            return request_text(host, "clear", var="bed_time", port=port)
        if action_name == "set_wake_time":
            return request_text(host, "set", var="wake_time", val=p.get("time"), port=port)
        if action_name == "clear_usage_limit":
            return request_text(host, "clear", var="daily_limit", port=port)
    except (ValueError, KeyError, TypeError) as exc:
        return False, f"Invalid value for {action_name}: {exc}"

    legacy = _legacy_panel_command(action_name, p)
    if legacy is not None:
        return send_command(host, legacy, port=port)
    return False, f"Unknown action: {action_name}"


def _parse_optional_int(raw: str | None) -> int | None:
    if raw is None or raw == "None":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def is_pc_reachable(host: str, port: int = DEFAULT_PORT, timeout: float = QUERY_TIMEOUT) -> bool:
    """True when the kid PC agent accepts TCP connections on port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def refresh_discovered_entry(
    ip: str, entry: dict[str, Any], port: int = DEFAULT_PORT
) -> None:
    """Update a cached scan entry with current reachability, lock, and user."""
    reachable = is_pc_reachable(ip, port=port)
    entry["reachable"] = reachable
    entry["status"] = "online" if reachable else "offline"
    if not reachable:
        entry["locked"] = False
        entry.pop("current_user", None)
        for key in (
            "daily_limit",
            "usage_limit",
            "manual_lock_active",
            "bed_time",
            "lock_times",
            "time_remaining",
        ):
            entry.pop(key, None)
        return

    entry["last_seen"] = datetime.now()
    status = check_pc_status(ip, port=port)
    entry["locked"] = status == "LOCKED"
    username = get_current_user(ip, port=port)
    if username:
        entry["current_user"] = username
    else:
        entry.pop("current_user", None)


def _resolve_hostname(ip: str, port: int) -> str:
    if ip in CUSTOM_PC_NAMES:
        return CUSTOM_PC_NAMES[ip]
    try:
        resp = send_request(ip, "get", var="name", port=port)
        if resp.ok and resp.result:
            return str(resp.result)
    except (OSError, proto.ProtocolError):
        pass
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except OSError:
        return f"PC at {ip}"


def scan_for_servers(
    port: int = DEFAULT_PORT,
    subnet: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Scan a network for hosts with the kid PC agent listening on port."""
    network, _network_label = parse_scan_subnet(subnet)
    discovered: dict[str, dict[str, Any]] = {}
    lock = threading.Lock()

    def check_host(ip: ipaddress.IPv4Address) -> None:
        ip_str = str(ip)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SCAN_CONNECT_TIMEOUT)
                if s.connect_ex((ip_str, port)) != 0:
                    return
        except OSError:
            return

        hostname = _resolve_hostname(ip_str, port)
        entry = {
            "hostname": hostname,
            "status": "online",
            "last_seen": datetime.now(),
        }
        with lock:
            discovered[ip_str] = entry

    threads = [threading.Thread(target=check_host, args=(ip,)) for ip in network.hosts()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return discovered


def check_pc_status(ip: str, port: int = DEFAULT_PORT) -> str:
    """Return LOCKED, UNLOCKED, or UNKNOWN."""
    try:
        resp = send_request(ip, "get", var="status", port=port)
    except (OSError, proto.ProtocolError):
        return "UNKNOWN"
    return str(resp.result) if resp.ok and resp.result else "UNKNOWN"


def get_current_user(ip: str, port: int = DEFAULT_PORT) -> str | None:
    try:
        resp = send_request(ip, "get", var="current_user", port=port)
    except (OSError, proto.ProtocolError):
        return None
    if resp.ok and resp.result is not None:
        return str(resp.result)
    return None


def get_daily_limit(ip: str, port: int = DEFAULT_PORT) -> int | None:
    return _parse_optional_int(query_command(ip, "GET_DAILY_LIMIT", port=port))


def get_usage_limit(ip: str, port: int = DEFAULT_PORT) -> int | None:
    """Legacy alias for get_daily_limit."""
    return get_daily_limit(ip, port=port)


def get_bed_time(ip: str, port: int = DEFAULT_PORT) -> str | None:
    raw = query_command(ip, "GET_BED_TIME", port=port)
    if raw is None or raw == "None":
        return None
    return raw


def get_manual_lock(ip: str, port: int = DEFAULT_PORT) -> bool:
    return query_command(ip, "GET_MANUAL_LOCK", port=port) == "YES"


def get_lock_times(ip: str, port: int = DEFAULT_PORT) -> list[str] | None:
    """Legacy: returns a single bedtime as a one-item list."""
    bed = get_bed_time(ip, port=port)
    if bed is None:
        return None
    return [bed]


def get_wake_time(ip: str, port: int = DEFAULT_PORT) -> str | None:
    """Return wake-up time as HH:MM, or None if the agent did not respond."""
    return query_command(ip, "GET_WAKE_TIME", port=port)


def get_cumulative_extension_seconds(ip: str, port: int = DEFAULT_PORT) -> int | None:
    return _parse_optional_int(query_command(ip, "GET_CUMULATIVE_EXTENSION", port=port))


def get_accumulated_seconds(ip: str, port: int = DEFAULT_PORT) -> int | None:
    return _parse_optional_int(query_command(ip, "GET_ACCUMULATED_SECONDS", port=port))


def get_time_remaining(ip: str, port: int = DEFAULT_PORT) -> str | None:
    return query_command(ip, "GET_TIME_REMAINING", port=port)


def inspect_pc(host: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
    """Collect status and limits from a single kid PC in one round-trip."""
    settings = get_settings(host, port=port)
    if settings is None:
        raise ConnectionError(f"Cannot reach agent at {host}:{port}")

    status = settings.get("status") or "UNKNOWN"
    daily_limit = settings.get("daily_limit")
    bed_time = settings.get("bed_time")
    wake_time = settings.get("wake_time")
    extension_seconds = int(settings.get("cumulative_extension") or 0)
    accumulated_seconds = int(settings.get("accumulated_seconds") or 0)

    # time_remaining arrives as an integer count of minutes (or null); render it
    # the way the panel and CLI expect to display it.
    remaining_min = settings.get("time_remaining")
    time_remaining = f"{remaining_min} minutes" if remaining_min is not None else None

    lock_times: list[str] | None = [bed_time] if bed_time else None

    effective_limit: float | None
    if daily_limit is None and extension_seconds <= 0:
        effective_limit = None
    else:
        effective_limit = (daily_limit or 0) + extension_seconds / 60

    hostname = settings.get("name") or _resolve_hostname(host, port)

    return {
        "ip": host,
        "port": port,
        "hostname": hostname,
        "status": status,
        "locked": status == "LOCKED",
        "current_user": settings.get("current_user"),
        "daily_limit": daily_limit,
        "usage_limit": daily_limit,
        "bed_time": bed_time,
        "lock_times": lock_times,
        "wake_time": wake_time,
        "manual_lock_active": bool(settings.get("manual_lock")),
        "cumulative_extension_seconds": extension_seconds,
        "accumulated_seconds": accumulated_seconds,
        "effective_limit_minutes": effective_limit,
        "time_remaining": time_remaining,
        "reachable": True,
    }

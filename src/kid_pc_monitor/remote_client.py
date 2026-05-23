"""TCP client for kid PC agents (pc_control.py remote server on port 9999)."""

from __future__ import annotations

import ipaddress
import socket
import threading
from datetime import datetime
from typing import Any

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
    name = query_command(ip, "GET_NAME", port=port)
    if name:
        return name
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
    status = query_command(ip, "GET_STATUS", port=port)
    return status if status else "UNKNOWN"


def get_current_user(ip: str, port: int = DEFAULT_PORT) -> str | None:
    return query_command(ip, "GET_CURRENT_USER", port=port)


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
    """Collect status and limits from a single kid PC."""
    ok, _ = send_command(host, "GET_STATUS", port=port)
    if not ok:
        raise ConnectionError(f"Cannot reach agent at {host}:{port}")

    def q(cmd: str) -> str | None:
        return query_command(host, cmd, port=port)

    status = q("GET_STATUS")
    daily_limit = _parse_optional_int(q("GET_DAILY_LIMIT"))
    manual_lock_raw = q("GET_MANUAL_LOCK")
    bed_time_raw = q("GET_BED_TIME")
    wake_time = q("GET_WAKE_TIME")
    time_remaining = q("GET_TIME_REMAINING")
    extension_seconds = _parse_optional_int(q("GET_CUMULATIVE_EXTENSION")) or 0
    accumulated_seconds = _parse_optional_int(q("GET_ACCUMULATED_SECONDS")) or 0

    bed_time: str | None
    if bed_time_raw is None or bed_time_raw == "None":
        bed_time = None
    else:
        bed_time = bed_time_raw

    lock_times: list[str] | None = [bed_time] if bed_time else None

    effective_limit: float | None
    if daily_limit is None and extension_seconds <= 0:
        effective_limit = None
    else:
        effective_limit = (daily_limit or 0) + extension_seconds / 60

    return {
        "ip": host,
        "port": port,
        "hostname": _resolve_hostname(host, port),
        "status": status or "UNKNOWN",
        "locked": status == "LOCKED",
        "current_user": q("GET_CURRENT_USER"),
        "daily_limit": daily_limit,
        "usage_limit": daily_limit,
        "bed_time": bed_time,
        "lock_times": lock_times,
        "wake_time": wake_time,
        "manual_lock_active": manual_lock_raw == "YES",
        "cumulative_extension_seconds": extension_seconds,
        "accumulated_seconds": accumulated_seconds,
        "effective_limit_minutes": effective_limit,
        "time_remaining": time_remaining,
        "reachable": True,
    }

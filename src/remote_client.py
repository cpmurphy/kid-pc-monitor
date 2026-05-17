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


def get_local_ip() -> str:
    """Primary IPv4 address used for outbound traffic."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


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


def get_usage_limit(ip: str, port: int = DEFAULT_PORT) -> int | None:
    limit = query_command(ip, "GET_USAGE_LIMIT", port=port)
    if limit is None or limit == "None":
        return None
    try:
        return int(limit)
    except ValueError:
        return None


def get_lock_times(ip: str, port: int = DEFAULT_PORT) -> list[str] | None:
    times = query_command(ip, "GET_LOCK_TIMES", port=port)
    if times is None or times == "None":
        return None
    return [t.strip() for t in times.split(",") if t.strip()]


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
    usage_raw = q("GET_USAGE_LIMIT")
    lock_times_raw = q("GET_LOCK_TIMES")
    time_remaining = q("GET_TIME_REMAINING")

    usage_limit: int | None
    if usage_raw is None or usage_raw == "None":
        usage_limit = None
    else:
        try:
            usage_limit = int(usage_raw)
        except ValueError:
            usage_limit = None

    lock_times: list[str] | None
    if lock_times_raw is None or lock_times_raw == "None":
        lock_times = None
    else:
        lock_times = [t.strip() for t in lock_times_raw.split(",") if t.strip()]

    return {
        "ip": host,
        "port": port,
        "hostname": _resolve_hostname(host, port),
        "status": status or "UNKNOWN",
        "locked": status == "LOCKED",
        "current_user": q("GET_CURRENT_USER"),
        "usage_limit": usage_limit,
        "lock_times": lock_times,
        "time_remaining": time_remaining,
        "reachable": True,
    }

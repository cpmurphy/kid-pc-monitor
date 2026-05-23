"""Local IPv4 discovery without contacting external hosts."""

from __future__ import annotations

import platform
import re
import socket
import struct
import subprocess
from pathlib import Path
from typing import Callable

# RFC 5737 TEST-NET-1 — used only to ask the kernel which source address routing
# would choose; no packets are sent for UDP connect().
_ROUTING_PROBE_HOST = "192.0.2.1"
_ROUTING_PROBE_PORT = 1
_ROUTING_PROBE_TIMEOUT = 2.0

# Linux /proc/net/route flags (linux/route.h)
_RTF_UP = 0x1
_RTF_GATEWAY = 0x2


def get_primary_ipv4() -> str | None:
    """
    Return the machine's primary IPv4 address, if one can be determined.

    Uses OS interface and routing information when possible. Falls back to a
    local routing-table lookup against TEST-NET-1 (no traffic to public IPs).
    """
    for resolver in _platform_resolvers():
        ip = resolver()
        if ip:
            return ip
    return _ipv4_from_routing_socket()


def get_local_ip() -> str:
    """Primary IPv4 for display and scanning; 127.0.0.1 when unknown."""
    return get_primary_ipv4() or "127.0.0.1"


def _platform_resolvers() -> list[Callable[[], str | None]]:
    system = platform.system()
    if system == "Linux":
        return [_linux_primary_ipv4]
    if system == "Windows":
        # Prefer routing-table lookup: no subprocess, no visible console flash.
        return [_ipv4_from_routing_socket, _hostname_ipv4]
    if system == "Darwin":
        return [_darwin_primary_ipv4, _hostname_ipv4]
    return [_hostname_ipv4]


def _usable_ipv4(ip: str | None) -> str | None:
    if not ip or ip.startswith("127.") or ip.startswith("169.254."):
        return None
    try:
        addr = socket.inet_aton(ip)
    except OSError:
        return None
    if addr == b"\x00\x00\x00\x00":
        return None
    return ip


def _hostname_ipv4() -> str | None:
    try:
        _name, _aliases, addresses = socket.gethostbyname_ex(socket.gethostname())
    except OSError:
        return None
    for ip in addresses:
        usable = _usable_ipv4(ip)
        if usable:
            return usable
    return None


def _linux_default_interface_from_proc(proc_text: str) -> str | None:
    best_iface: str | None = None
    best_metric: int | None = None
    for line in proc_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, dest, _gateway, flags_hex, *_rest = (
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            *fields[4:],
        )
        if dest != "00000000":
            continue
        try:
            flags = int(flags_hex, 16)
            metric = int(fields[6])
        except (ValueError, IndexError):
            continue
        if not (flags & _RTF_UP):
            continue
        if best_metric is None or metric < best_metric:
            best_metric = metric
            best_iface = iface
    return best_iface


def _linux_ipv4_for_interface(ifname: str) -> str | None:
    import fcntl

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", ifname.encode()[:15])
        res = fcntl.ioctl(sock.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _linux_primary_ipv4() -> str | None:
    proc_path = Path("/proc/net/route")
    if not proc_path.is_file():
        return None
    try:
        proc_text = proc_path.read_text(encoding="utf-8")
    except OSError:
        return None
    iface = _linux_default_interface_from_proc(proc_text)
    if not iface:
        return None
    return _usable_ipv4(_linux_ipv4_for_interface(iface))


def _windows_primary_ipv4() -> str | None:
    script = (
        "Get-NetIPAddress -AddressFamily IPv4 "
        "| Where-Object { "
        "$_.IPAddress -ne '127.0.0.1' "
        "-and $_.PrefixOrigin -ne 'WellKnown' "
        "} "
        "| Sort-Object InterfaceMetric "
        "| Select-Object -First 1 -ExpandProperty IPAddress"
    )
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return _usable_ipv4(out.splitlines()[0] if out else None)


def _darwin_primary_ipv4() -> str | None:
    try:
        route_out = subprocess.check_output(
            ["route", "-n", "get", "default"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    match = re.search(r"interface:\s*(\S+)", route_out)
    if not match:
        return None
    iface = match.group(1)
    try:
        ip = subprocess.check_output(
            ["ipconfig", "getifaddr", iface],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return _usable_ipv4(ip)


def _ipv4_from_routing_socket() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_ROUTING_PROBE_TIMEOUT)
            sock.connect((_ROUTING_PROBE_HOST, _ROUTING_PROBE_PORT))
            return _usable_ipv4(sock.getsockname()[0])
    except OSError:
        return None

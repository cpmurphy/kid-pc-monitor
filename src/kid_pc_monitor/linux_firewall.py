"""Decide whether a Linux host firewall will block the web panel's ports.

Used by ``scripts/install_web_panel_linux.sh`` so the installer only suggests
firewall changes when a firewall is actually active. Everything here runs
without root: firewalld answers read-only queries over D-Bus, and ufw's
enabled flag and default policy live in world-readable files. When the rules
themselves cannot be read, the report says so instead of guessing.

Run as ``python -m kid_pc_monitor.linux_firewall [--interactive] PORT...``.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from kid_pc_monitor.network import get_linux_default_interface

UFW_CONF = Path("/etc/ufw/ufw.conf")
UFW_DEFAULTS = Path("/etc/default/ufw")
UFW_USER_RULES = Path("/etc/ufw/user.rules")

# Services that load raw nftables/iptables rules we cannot read without root.
_RAW_FIREWALL_SERVICES = ("nftables", "iptables", "netfilter-persistent")

# Returns (exit status, stdout); status 127 when the command is not installed.
Runner = Callable[[Sequence[str]], tuple[int, str]]
# Returns the file's text, or None when it is missing or unreadable.
Reader = Callable[[Path], str | None]


@dataclass(frozen=True)
class FirewallReport:
    """Outcome of :func:`check_firewall`.

    ``status`` is one of:

    * ``"none"`` — no active firewall found; nothing to change.
    * ``"open"`` — a firewall is active and already allows every port.
    * ``"blocked"`` — a firewall is active and does not allow ``blocked_ports``.
    * ``"unknown"`` — a firewall is active but its rules could not be read.
    """

    status: str
    firewall: str | None = None
    blocked_ports: tuple[int, ...] = ()
    commands: tuple[tuple[str, ...], ...] = ()
    detail: str = ""


def _run(cmd: Sequence[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return 127, ""
    except (subprocess.SubprocessError, OSError):
        return 1, ""
    return completed.returncode, completed.stdout


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _port_spec_covers(spec: str, port: int) -> bool:
    """True when a spec like ``5000``, ``5000/tcp``, ``1025-65535/tcp`` or ``any`` allows TCP ``port``."""
    number, _sep, proto = spec.partition("/")
    if proto and proto not in ("tcp", "any"):
        return False
    if number.lower() in ("any", "anywhere"):
        return True
    low, sep, high = number.replace(":", "-").partition("-")
    try:
        if sep:
            return int(low) <= port <= int(high)
        return int(low) == port
    except ValueError:
        return False


def _shell_config_value(text: str, key: str) -> str | None:
    for line in text.splitlines():
        name, sep, value = line.strip().partition("=")
        if sep and name == key:
            return value.strip().strip("\"'")
    return None


# --- firewalld --------------------------------------------------------------


def _firewalld_zone(run: Runner, iface: str | None) -> str | None:
    if iface:
        status, out = run(["firewall-cmd", f"--get-zone-of-interface={iface}"])
        if status == 0 and out.strip():
            return out.strip()
    status, out = run(["firewall-cmd", "--get-default-zone"])
    if status == 0 and out.strip():
        return out.strip()
    return None


def _check_firewalld(run: Runner, ports: Sequence[int], iface: str | None) -> FirewallReport | None:
    status, out = run(["firewall-cmd", "--state"])
    if status != 0 or out.strip() != "running":
        return None
    zone = _firewalld_zone(run, iface)
    list_status, listed = 1, ""
    if zone:
        list_status, listed = run(["firewall-cmd", f"--zone={zone}", "--list-ports"])
    if zone is None or list_status != 0:
        return FirewallReport(
            status="unknown",
            firewall="firewalld",
            commands=(("sudo", "firewall-cmd", "--list-all"),),
            detail="firewalld is running, but its rules could not be read without root.",
        )
    specs = listed.split()
    blocked = tuple(p for p in ports if not any(_port_spec_covers(s, p) for s in specs))
    if not blocked:
        return FirewallReport(status="open", firewall="firewalld", detail=f"zone {zone}")
    add_ports = [f"--add-port={p}/tcp" for p in blocked]
    return FirewallReport(
        status="blocked",
        firewall="firewalld",
        blocked_ports=blocked,
        commands=(
            ("sudo", "firewall-cmd", f"--zone={zone}", "--permanent", *add_ports),
            ("sudo", "firewall-cmd", "--reload"),
        ),
        detail=f"zone {zone}",
    )


# --- ufw --------------------------------------------------------------------


def _ufw_allowed_specs_from_rules(text: str) -> list[str]:
    """Port specs from ``### tuple ### allow <proto> <port> ... in`` lines in user.rules."""
    specs: list[str] = []
    for line in text.splitlines():
        fields = line.split()
        if fields[:3] != ["###", "tuple", "###"] or len(fields) < 6:
            continue
        action, proto, port = fields[3], fields[4], fields[5]
        if action != "allow" or fields[-1] != "in":
            continue
        specs.extend(f"{p}/{proto}" for p in port.split(","))
    return specs


def _ufw_allowed_specs_from_status(text: str) -> list[str]:
    """Port specs from ``sudo ufw status`` lines such as ``5000/tcp  ALLOW  Anywhere``."""
    specs: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^(\S+)\s+(?:\(v6\)\s+)?ALLOW(?: IN)?\s", line)
        if match:
            specs.extend(match.group(1).split(","))
    return specs


def _check_ufw(run: Runner, read: Reader, ports: Sequence[int]) -> FirewallReport | None:
    conf = read(UFW_CONF)
    if conf is None or (_shell_config_value(conf, "ENABLED") or "").lower() != "yes":
        return None
    defaults = read(UFW_DEFAULTS) or ""
    if _shell_config_value(defaults, "DEFAULT_INPUT_POLICY") == "ACCEPT":
        return FirewallReport(
            status="open", firewall="ufw", detail="default incoming policy is allow"
        )

    rules = read(UFW_USER_RULES)
    if rules is not None:
        specs = _ufw_allowed_specs_from_rules(rules)
    else:
        # user.rules is root-only on most distros; use cached sudo credentials if any.
        status, out = run(["sudo", "-n", "ufw", "status"])
        specs = _ufw_allowed_specs_from_status(out) if status == 0 else None

    allow_cmds = tuple(("sudo", "ufw", "allow", f"{p}/tcp") for p in ports)
    if specs is None:
        # `ufw allow` skips rules that already exist, so suggesting it is harmless.
        return FirewallReport(
            status="unknown",
            firewall="ufw",
            blocked_ports=tuple(ports),
            commands=allow_cmds,
            detail="ufw is enabled, but its rules could not be read without root.",
        )
    blocked = tuple(p for p in ports if not any(_port_spec_covers(s, p) for s in specs))
    if not blocked:
        return FirewallReport(status="open", firewall="ufw")
    return FirewallReport(
        status="blocked",
        firewall="ufw",
        blocked_ports=blocked,
        commands=tuple(("sudo", "ufw", "allow", f"{p}/tcp") for p in blocked),
    )


# --- raw nftables / iptables -----------------------------------------------


def _check_raw_services(run: Runner) -> FirewallReport | None:
    for service in _RAW_FIREWALL_SERVICES:
        status, out = run(["systemctl", "is-active", f"{service}.service"])
        if status == 0 and out.strip() == "active":
            return FirewallReport(
                status="unknown",
                firewall=service,
                commands=(("sudo", "nft", "list", "ruleset"),),
                detail=f"The {service} service is active; its rules can only be read as root.",
            )
    return None


def check_firewall(
    ports: Iterable[int],
    *,
    run: Runner = _run,
    read: Reader = _read,
    iface: str | None = None,
) -> FirewallReport:
    """Report whether an active host firewall would block inbound TCP ``ports``."""
    port_list = list(ports)
    if iface is None:
        iface = get_linux_default_interface()
    for report in (
        _check_firewalld(run, port_list, iface),
        _check_ufw(run, read, port_list),
        _check_raw_services(run),
    ):
        if report is not None:
            return report
    return FirewallReport(status="none")


def format_report(report: FirewallReport, ports: Sequence[int]) -> str:
    port_text = " and ".join(f"{p}/tcp" for p in ports)
    detail = f" ({report.detail})" if report.detail and report.status == "open" else ""
    if report.status == "none":
        return (
            "Firewall: no active firewall found (checked firewalld, ufw, nftables/iptables);\n"
            f"  no changes needed for {port_text}."
        )
    if report.status == "open":
        return f"Firewall: {report.firewall} already allows {port_text}{detail}."
    lines: list[str] = []
    if report.status == "blocked":
        blocked = " and ".join(f"{p}/tcp" for p in report.blocked_ports)
        lines.append(f"Firewall: {report.firewall} is active and blocks {blocked}.")
        lines.append("  Kid PCs and your phone cannot reach the panel until these are allowed:")
    else:
        lines.append(f"Firewall: {report.detail}")
        if report.firewall == "ufw":
            lines.append(f"  If you have not already allowed {port_text}, run:")
        else:
            lines.append(f"  Check that it allows inbound {port_text}, e.g.:")
    lines.extend(f"    {shlex.join(cmd)}" for cmd in report.commands)
    return "\n".join(lines)


def _can_offer_fix(report: FirewallReport) -> bool:
    """Only ufw/firewalld changes are offered; ufw ``allow`` is safe to repeat."""
    if report.status == "blocked":
        return report.firewall in ("ufw", "firewalld")
    return report.status == "unknown" and report.firewall == "ufw"


def _offer_to_run(report: FirewallReport) -> int:
    if not _can_offer_fix(report):
        return 0
    try:
        answer = input("  Run these now with sudo? [y/N]: ").strip().lower()
    except EOFError:
        return 0
    if answer not in ("y", "yes"):
        return 0
    for cmd in report.commands:
        status = subprocess.run(list(cmd), check=False).returncode
        if status != 0:
            print(f"  Command failed ({status}): {shlex.join(cmd)}", file=sys.stderr)
            return status
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check whether a Linux firewall blocks the web panel ports."
    )
    parser.add_argument("ports", nargs="+", type=int)
    parser.add_argument(
        "--interactive", action="store_true", help="offer to run suggested commands"
    )
    args = parser.parse_args(argv)
    report = check_firewall(args.ports)
    print(format_report(report, args.ports))
    if args.interactive and sys.stdin.isatty():
        return _offer_to_run(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

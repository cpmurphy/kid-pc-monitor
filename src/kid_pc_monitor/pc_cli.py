#!/usr/bin/env python3
"""Command-line client for Kid PC Monitor agents (pc_control.py)."""

from __future__ import annotations

import argparse
import json
import sys

from kid_pc_monitor.remote_client import (
    DEFAULT_PORT,
    inspect_pc,
    parse_scan_subnet,
    scan_for_servers,
    send_command,
)

# Maps CLI subcommand names to wire protocol commands (or builders).
ACTION_COMMANDS: dict[str, str | None] = {
    "lock": "LOCK",
    "shutdown": "SHUTDOWN",
    "clear-usage-limit": "CLEAR_USAGE_LIMIT",
    "clear-lock-times": "CLEAR_LOCK_TIMES",
    "clear-manual-lock": "CLEAR_MANUAL_LOCK",
    "clear-all": "CLEAR_ALL",
    "help": "HELP",
}


def _add_host_port(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("host", help="Kid PC IPv4 address")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Agent TCP port (default: {DEFAULT_PORT})",
    )


def _run_action(host: str, command: str, port: int, json_out: bool) -> int:
    ok, response = send_command(host, command, port=port)
    if json_out:
        print(json.dumps({"success": ok, "response": response}))
    elif ok:
        print(response)
    else:
        print(f"Error: {response}", file=sys.stderr)
    return 0 if ok else 1


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        _network, label = parse_scan_subnet(args.subnet)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"Scanning {label} for agents on port {args.port}...")

    pcs = scan_for_servers(port=args.port, subnet=args.subnet)

    if args.json:
        payload = {
            "network": label,
            "count": len(pcs),
            "pcs": [
                {"ip": ip, "hostname": info["hostname"]}
                for ip, info in sorted(pcs.items(), key=lambda x: x[0])
            ],
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0

    if not pcs:
        print(
            "No kid PCs found. Check that agents are running and "
            f"firewalls allow TCP {args.port}."
        )
        return 1

    print(f"\nFound {len(pcs)} PC(s) on {label}:\n")
    print(f"{'IP':<16} {'NAME'}")
    print("-" * 40)
    for ip, info in sorted(pcs.items(), key=lambda x: x[0]):
        print(f"{ip:<16} {info['hostname']}")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    try:
        info = inspect_pc(args.host, port=args.port)
    except ConnectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(info, indent=2, default=str))
        return 0

    lock_label = "yes" if info["locked"] else "no"
    print(f"\n{info['hostname']} ({info['ip']}:{info['port']})")
    print("-" * 40)
    print(f"  Screen locked:     {lock_label} ({info['status']})")
    print(f"  Windows user:      {info['current_user'] or '—'}")
    limit = info["usage_limit"]
    print(f"  Daily usage limit: {f'{limit} min' if limit is not None else 'none'}")
    manual = "yes" if info["manual_lock_active"] else "no"
    print(f"  Manual lock:       {manual}")
    times = info["lock_times"]
    if times:
        print(f"  Bedtime locks:     {', '.join(times)}")
    else:
        print("  Bedtime locks:     none")
    wake = info.get("wake_time")
    print(f"  Wake-up time:      {wake or '—'}")
    remaining = info["time_remaining"]
    print(f"  Time remaining:    {remaining or '—'}")
    return 0


def _cmd_action(args: argparse.Namespace) -> int:
    name = args.action_name
    host = args.host
    port = args.port

    if name == "message":
        command = f"MESSAGE:{args.text}"
    elif name == "set-limit":
        command = f"SET_LIMIT:{args.minutes}"
    elif name == "add-lock-time":
        command = f"ADD_LOCK_TIME:{args.time}"
    elif name == "set-wake-time":
        command = f"SET_WAKE_TIME:{args.time}"
    elif name == "extend-time":
        command = f"EXTEND_TIME:{args.minutes}"
    elif name == "raw":
        command = args.command
    else:
        command = ACTION_COMMANDS.get(name)
        if command is None:
            print(f"Unknown action: {name}", file=sys.stderr)
            return 2

    return _run_action(host, command, port, args.json)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pc_cli",
        description="Scan for and control kid PCs running the Kid PC Monitor agent.",
        epilog=(
            "Examples:\n"
            "  %(prog)s scan\n"
            "  %(prog)s scan --subnet 192.168.1.0/24\n"
            "  %(prog)s inspect 192.168.1.105\n"
            "  %(prog)s set-limit 192.168.1.105 60\n"
            "  %(prog)s add-lock-time 192.168.1.105 21:00\n"
            "  %(prog)s set-wake-time 192.168.1.105 07:00\n"
            "  %(prog)s lock 192.168.1.105\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON output",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan the local network for kid PCs")
    p_scan.add_argument(
        "--subnet",
        metavar="NET",
        help=(
            "Network to scan (default: local /24). "
            "Examples: 192.168.1.0/24, 192.168.1, 192.168.1.50"
        ),
    )
    p_scan.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_scan.add_argument("-q", "--quiet", action="store_true", help="Suppress progress text")
    p_scan.set_defaults(func=_cmd_scan)

    p_inspect = sub.add_parser("inspect", help="Show status and limits for one PC")
    _add_host_port(p_inspect)
    p_inspect.set_defaults(func=_cmd_inspect)

    def add_action(name: str, help_text: str, **kwargs) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text)
        _add_host_port(p)
        for key, value in kwargs.items():
            p.add_argument(key, **value)
        p.set_defaults(func=_cmd_action, action_name=name)
        return p

    add_action("lock", "Lock the PC and keep it locked until clear-all")
    add_action("shutdown", "Shut down the PC (60 second warning)")
    add_action(
        "message",
        "Show a popup message on the PC",
        text={"metavar": "TEXT", "help": "Message body"},
    )
    add_action(
        "set-limit",
        "Set daily usage limit and reset the usage timer",
        minutes={"type": int, "metavar": "MINUTES", "help": "Minutes allowed today"},
    )
    add_action(
        "add-lock-time",
        "Add a scheduled bedtime lock (HH:MM, 24-hour)",
        time={"metavar": "HH:MM", "help": "Lock time, e.g. 21:00"},
    )
    add_action(
        "set-wake-time",
        "Set morning wake-up time when locks lift (HH:MM, 24-hour)",
        time={"metavar": "HH:MM", "help": "Wake-up time, e.g. 07:00"},
    )
    add_action(
        "extend-time",
        "Add minutes to the current daily usage limit",
        minutes={"type": int, "metavar": "MINUTES", "help": "Minutes to add"},
    )
    add_action("clear-usage-limit", "Remove the daily usage limit")
    add_action("clear-lock-times", "Remove all scheduled bedtime locks")
    add_action("clear-manual-lock", "Remove manual lock enforcement")
    add_action("clear-all", "Remove usage limit, bedtime locks, and manual lock")
    add_action("help", "Show commands supported by the agent")

    p_raw = sub.add_parser(
        "raw",
        help="Send a raw protocol command (e.g. GET_STATUS)",
    )
    _add_host_port(p_raw)
    p_raw.add_argument("command", help="Command string sent to the agent")
    p_raw.set_defaults(func=_cmd_action, action_name="raw")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

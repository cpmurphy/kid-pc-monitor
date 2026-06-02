"""Kid PC Monitor agent process: logging, TCP server, and entry point."""

from __future__ import annotations

import getpass
import logging
import os
import socket
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from typing import Any

from kid_pc_monitor import agent_protocol, request_dispatcher
from kid_pc_monitor.host_platform import HostPlatform, get_default_platform
from kid_pc_monitor.pc_time_control import PCTimeControl, data_dir
from kid_pc_monitor.remote_control_server import DEFAULT_AGENT_PORT, RemoteControlServer

log_file = data_dir / "pc_control.log"
AGENT_PORT = DEFAULT_AGENT_PORT

DEFAULT_LOG_MAX_BYTES = 200_000
DEFAULT_LOG_BACKUP_COUNT = 4


def _log_level_from_env() -> int:
    raw = os.environ.get("KID_PC_MONITOR_LOG_LEVEL", "INFO").strip().upper()
    return getattr(logging, raw, logging.INFO)


def _configure_logging() -> int:
    """Append to the per-user log; rotate by size into numbered backups."""
    level = _log_level_from_env()
    root = logging.getLogger()
    root.setLevel(level)
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    handler = RotatingFileHandler(
        log_file,
        maxBytes=DEFAULT_LOG_MAX_BYTES,
        backupCount=DEFAULT_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root.addHandler(handler)
    return level


_log_level = _configure_logging()
logger = logging.getLogger("kid_pc_monitor")


def log_connectivity_diagnostics(platform: HostPlatform) -> None:
    """Delegate OS-specific network/firewall diagnostics to the platform layer."""
    platform.log_connectivity_diagnostics(
        logger,
        agent_port=AGENT_PORT,
        log_file=str(log_file),
        log_level_name=logging.getLevelName(_log_level),
        python_executable=sys.executable,
    )


def main() -> int:
    script_path = os.path.abspath(__file__)

    def check_port_availability(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False

    logger.info(
        "Agent process starting (pid=%s, user=%s, script=%s)",
        os.getpid(),
        getpass.getuser(),
        script_path,
    )
    platform = get_default_platform()
    log_connectivity_diagnostics(platform)

    if not check_port_availability(AGENT_PORT):
        logger.error(
            "Port %s already in use — another KidPCMonitor instance is probably "
            "already running. Exiting duplicate startup.",
            AGENT_PORT,
        )
        return 1

    # Create control instance
    control = PCTimeControl(platform=platform)

    # Enforce usage allowance, bedtime, and warnings (separate from the TCP server)
    enforcement_thread = threading.Thread(target=control.run_monitor, daemon=True)
    enforcement_thread.start()

    # Start remote control server
    remote = RemoteControlServer()
    server_thread = threading.Thread(target=remote.start_server, args=(control,))
    server_thread.daemon = True
    server_thread.start()

    if not remote.listener_ready.wait(timeout=10):
        logger.error(
            "TCP listener did not start on port %s within 10s — check %s",
            AGENT_PORT,
            log_file,
        )
        control.show_message(
            "Failed to start network server!\nCheck firewall settings and try again.",
            "Server Error",
        )
        return 1

    logger.info(
        "Agent running (enforcement + TCP %s on 0.0.0.0). "
        "Verbose command logging: set KID_PC_MONITOR_LOG_LEVEL=DEBUG",
        remote.port,
    )
    print("Server is running. Press Ctrl+C to stop.")

    try:
        # Keep main thread alive while server runs
        while remote.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        remote.stop_server()
        server_thread.join(2)  # Wait up to 2 seconds for thread to finish
        print("Server stopped.")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def handle_request(
    control: Any,
    body: str,
    *,
    secret: str,
    now: int | None = None,
) -> str:
    """Top-level server entry: authenticate, dispatch, and sign, never raising.

    Any :class:`ProtocolError` becomes a signed failure response; unexpected
    exceptions become a signed ``internal_error`` response.  Every response is
    signed with this agent's per-host key so the panel can authenticate it.
    """
    hostname = control.platform.get_hostname()
    req_id: str | None = None
    response_version = agent_protocol.peek_version(body)
    try:
        req = agent_protocol.parse_request(body, secret=secret, hostname=hostname, now=now)
        req_id = req.id
        response_version = req.version
        content = request_dispatcher.dispatch(control, req)
    except agent_protocol.ProtocolError as exc:
        content = agent_protocol.error_content(exc.code, exc.message)
        req_id = exc.req_id or req_id
    except Exception as exc:  # noqa: BLE001 - defensive catch-all per design
        content = agent_protocol.error_content(agent_protocol.INTERNAL_ERROR, str(exc))
    return agent_protocol.sign_response(
        content,
        secret=secret,
        hostname=hostname,
        req_id=req_id,
        version=response_version,
    )


if __name__ == "__main__":
    raise SystemExit(main())

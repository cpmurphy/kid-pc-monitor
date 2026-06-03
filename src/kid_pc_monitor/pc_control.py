"""Kid PC Monitor agent process: logging, TCP server, and entry point."""

from __future__ import annotations

import getpass
import logging
import os
import socket
import threading
import time
from logging.handlers import RotatingFileHandler

from kid_pc_monitor.agent_diagnostics import AGENT_LISTEN_PORT, log_connectivity_diagnostics
from kid_pc_monitor.host_platform import get_default_platform
from kid_pc_monitor.pc_time_control import PCTimeControl, data_dir
from kid_pc_monitor.remote_control_server import RemoteControlServer

log_file = data_dir / "pc_control.log"
AGENT_PORT = AGENT_LISTEN_PORT

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


_configure_logging()
logger = logging.getLogger("kid_pc_monitor")


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


if __name__ == "__main__":
    raise SystemExit(main())

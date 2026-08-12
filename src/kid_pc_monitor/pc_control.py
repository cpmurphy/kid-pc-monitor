"""Kid PC Monitor agent process: logging, enforcement, and reverse client."""

from __future__ import annotations

import getpass
import logging
import os
import threading
import time
from logging.handlers import RotatingFileHandler

from kid_pc_monitor.agent_diagnostics import log_connectivity_diagnostics
from kid_pc_monitor.agent_sync_client import start_agent_reverse_client
from kid_pc_monitor.host_platform import get_default_platform
from kid_pc_monitor.pc_time_control import PCTimeControl, data_dir

log_file = data_dir / "pc_control.log"

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

    logger.info(
        "Agent process starting (pid=%s, user=%s, script=%s)",
        os.getpid(),
        getpass.getuser(),
        script_path,
    )
    platform = get_default_platform()
    log_connectivity_diagnostics(platform)

    control = PCTimeControl(platform=platform)

    enforcement_thread = threading.Thread(target=control.run_monitor, daemon=True)
    enforcement_thread.start()

    reverse_client = start_agent_reverse_client(control)

    logger.info(
        "Agent running (enforcement + reverse TCP). "
        "Verbose command logging: set KID_PC_MONITOR_LOG_LEVEL=DEBUG"
    )
    print("Agent is running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down agent...")
        reverse_client.stop()
        print("Agent stopped.")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

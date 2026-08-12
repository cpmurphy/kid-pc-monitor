"""Connectivity diagnostics logging for the kid PC agent process."""

from __future__ import annotations

import logging
import os
import sys

from kid_pc_monitor.host_platform import HostPlatform
from kid_pc_monitor.pc_time_control import data_dir


def log_connectivity_diagnostics(platform: HostPlatform) -> None:
    """Delegate OS-specific network/firewall diagnostics to the platform layer."""
    raw = os.environ.get("KID_PC_MONITOR_LOG_LEVEL", "INFO").strip().upper()
    log_level_name = logging.getLevelName(getattr(logging, raw, logging.INFO))
    platform.log_connectivity_diagnostics(
        logging.getLogger("kid_pc_monitor"),
        log_file=str(data_dir / "pc_control.log"),
        log_level_name=log_level_name,
        python_executable=sys.executable,
    )

"""Background agent polling for the web panel."""

from __future__ import annotations

import logging
import random
import threading
import time

from kid_pc_monitor.remote_client import connection_failure_fields, inspect_pc
from kid_pc_monitor.scan_store import get_tracked_ips, prune_stale_tracked_ips
from kid_pc_monitor.snapshot_store import save_poll_snapshot, save_snapshot

logger = logging.getLogger(__name__)

POLL_INTERVAL_SEC = 60
INITIAL_JITTER_MIN_SEC = 5
INITIAL_JITTER_MAX_SEC = 55


def _poll_interval_sec() -> float:
    return float(POLL_INTERVAL_SEC)


def _cycle_sleep_sec(interval: float) -> float:
    jitter = max(0.0, min(interval * 0.1, 5.0))
    return random.uniform(interval - jitter, interval + jitter)


def poll_once() -> None:
    """Inspect all tracked PCs and update snapshots."""
    targets = get_tracked_ips()
    if not targets:
        logger.debug("Agent poll cycle skipped: no tracked PCs")
        return

    logger.debug("Agent poll cycle starting for %d PC(s)", len(targets))
    for ip, entry in targets.items():
        try:
            info = inspect_pc(ip)
            info["ip"] = ip
            save_poll_snapshot(info)
            if info.get("reachable") and info.get("current_user"):
                save_snapshot(info)
        except ConnectionError as exc:
            failure = {**entry, "ip": ip, **connection_failure_fields(exc)}
            save_poll_snapshot(failure)
        except Exception:
            logger.warning("Failed to poll agent at %s", ip, exc_info=True)
    pruned = prune_stale_tracked_ips()
    if pruned:
        logger.info("Pruned stale tracked PC(s): %s", ", ".join(sorted(pruned)))
    logger.debug("Agent poll cycle finished")


def _run(stop: threading.Event) -> None:
    interval = _poll_interval_sec()
    time.sleep(random.uniform(INITIAL_JITTER_MIN_SEC, INITIAL_JITTER_MAX_SEC))
    while not stop.is_set():
        try:
            poll_once()
        except Exception:
            logger.exception("Agent poll cycle failed")
        if stop.wait(timeout=_cycle_sleep_sec(interval)):
            break


def start_agent_poller() -> threading.Event:
    """Start the background agent poller; returns a stop event."""
    stop = threading.Event()
    thread = threading.Thread(target=_run, args=(stop,), name="agent-poller", daemon=True)
    thread.start()
    logger.info("Agent poller started (interval ~%.0fs)", _poll_interval_sec())
    return stop

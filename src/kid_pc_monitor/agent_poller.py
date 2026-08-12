"""Background maintenance for the web panel PC registry."""

from __future__ import annotations

import logging
import random
import threading
import time

from kid_pc_monitor.scan_store import prune_stale_tracked_ips

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
    """Prune stale tracked PCs (status updates come from reverse sessions)."""
    pruned = prune_stale_tracked_ips()
    if pruned:
        logger.info("Pruned stale tracked PC(s): %s", ", ".join(sorted(pruned)))
    else:
        logger.debug("Agent registry prune cycle finished (none stale)")


def _run(stop: threading.Event) -> None:
    interval = _poll_interval_sec()
    time.sleep(random.uniform(INITIAL_JITTER_MIN_SEC, INITIAL_JITTER_MAX_SEC))
    while not stop.is_set():
        try:
            poll_once()
        except Exception:
            logger.exception("Agent registry prune cycle failed")
        if stop.wait(timeout=_cycle_sleep_sec(interval)):
            break


def start_agent_poller() -> threading.Event:
    """Start the background registry pruner; returns a stop event."""
    stop = threading.Event()
    thread = threading.Thread(target=_run, args=(stop,), name="agent-poller", daemon=True)
    thread.start()
    logger.info("Agent registry pruner started (interval ~%.0fs)", _poll_interval_sec())
    return stop

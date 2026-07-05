"""Agent-side reverse polling client for the parent web panel."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import random
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from kid_pc_monitor import agent_protocol, request_dispatcher, shared_secret
from kid_pc_monitor.network import get_local_ip
from kid_pc_monitor.pc_time_control import data_dir
from kid_pc_monitor.remote_control_server import handle_request

if False:  # pragma: no cover - typing-only without importing Windows pieces at runtime.
    pass

logger = logging.getLogger("AgentSyncClient")

DEFAULT_PANEL_PORT = 5000
DISCOVERY_TIMEOUT_SEC = 0.5
POLL_TIMEOUT_SEC = 35
DEFAULT_POLL_AFTER_SEC = 5
MAX_DISCOVERY_HOSTS = 254
PANEL_URL_ENV = "KID_PC_MONITOR_PANEL_URL"
CACHE_FILE = "panel_url.txt"
DISCOVERY_MARKER = "kid-pc-monitor-panel"


def _cache_path():
    return data_dir / CACHE_FILE


def _normalize_panel_url(raw: str) -> str:
    url = raw.strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    return url


def _http_json(url: str, payload: dict[str, Any] | None, *, timeout: float) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    method = "GET"
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    req = UrlRequest(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as response:  # noqa: S310 - LAN URL controlled by config/discovery.
        body = response.read().decode("utf-8")
    return json.loads(body)


def _is_panel_url(base_url: str) -> bool:
    try:
        payload = _http_json(
            urljoin(base_url.rstrip("/") + "/", "agent/v1/discover"),
            None,
            timeout=DISCOVERY_TIMEOUT_SEC,
        )
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return False
    return payload.get("service") == DISCOVERY_MARKER


def _read_cached_panel_url() -> str:
    try:
        return _normalize_panel_url(_cache_path().read_text(encoding="utf-8"))
    except OSError:
        return ""


def _write_cached_panel_url(url: str) -> None:
    try:
        _cache_path().write_text(url.rstrip("/") + "\n", encoding="utf-8")
    except OSError:
        logger.debug("Could not write panel URL cache", exc_info=True)


def discover_panel_url() -> str | None:
    """Find the web panel URL using env/config cache, then local /24 scan."""
    for candidate in (
        _normalize_panel_url(os.environ.get(PANEL_URL_ENV, "")),
        _read_cached_panel_url(),
    ):
        if candidate and _is_panel_url(candidate):
            _write_cached_panel_url(candidate)
            return candidate

    try:
        network = ipaddress.ip_network(f"{get_local_ip()}/24", strict=False)
    except ValueError:
        return None

    hosts = list(network.hosts())[:MAX_DISCOVERY_HOSTS]
    random.shuffle(hosts)
    for ip in hosts:
        candidate = f"http://{ip}:{DEFAULT_PANEL_PORT}"
        if _is_panel_url(candidate):
            logger.info("Discovered Kid PC Monitor panel at %s", candidate)
            _write_cached_panel_url(candidate)
            return candidate
    return None


def build_status_frame(control: Any, secret: str) -> str:
    hostname = control.platform.get_hostname()
    req = agent_protocol.Request(
        version=agent_protocol.CLIENT_DEFAULT_VERSION,
        id=None,
        action="get",
        var="settings",
        name=hostname,
    )
    content = request_dispatcher.dispatch(control, req)
    return agent_protocol.sign_response(content, secret=secret, hostname=hostname)


class AgentSyncClient:
    def __init__(self, control: Any):
        self.control = control
        self.panel_url: str | None = None
        self.pending_results: list[dict[str, Any]] = []
        self.running = False

    def _secret(self) -> str | None:
        return shared_secret.load_shared_secret()

    def _poll_url(self) -> str:
        assert self.panel_url is not None
        return urljoin(self.panel_url.rstrip("/") + "/", "agent/v1/poll")

    def _execute_commands(self, commands: list[dict[str, Any]], secret: str) -> None:
        for command in commands:
            command_id = command.get("id")
            frame = command.get("request")
            if not isinstance(command_id, int) or not isinstance(frame, str):
                continue
            response = handle_request(self.control, frame, secret=secret)
            self.pending_results.append({"command_id": command_id, "response": response})

    def poll_once(self) -> None:
        secret = self._secret()
        if not secret:
            logger.error("No shared secret configured; reverse polling disabled")
            time.sleep(30)
            return
        if self.panel_url is None:
            self.panel_url = discover_panel_url()
            if self.panel_url is None:
                logger.debug("No Kid PC Monitor panel discovered on this LAN")
                time.sleep(30)
                return

        payload = {
            "status": build_status_frame(self.control, secret),
            "results": self.pending_results,
        }
        try:
            response = _http_json(self._poll_url(), payload, timeout=POLL_TIMEOUT_SEC)
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
            logger.warning("Reverse poll to panel failed; rediscovering", exc_info=True)
            self.panel_url = None
            time.sleep(10)
            return

        self.pending_results = []
        commands = response.get("commands")
        if isinstance(commands, list):
            self._execute_commands(commands, secret)
        poll_after = response.get("poll_after_sec", DEFAULT_POLL_AFTER_SEC)
        try:
            delay = max(1.0, min(float(poll_after), 30.0))
        except (TypeError, ValueError):
            delay = DEFAULT_POLL_AFTER_SEC
        time.sleep(delay + random.uniform(0, 1.5))

    def run(self) -> None:
        self.running = True
        while self.running:
            try:
                self.poll_once()
            except Exception:
                logger.exception("Reverse polling cycle failed")
                time.sleep(15)

    def stop(self) -> None:
        self.running = False


def start_agent_sync_poller(control: Any) -> AgentSyncClient:
    client = AgentSyncClient(control)
    thread = threading.Thread(target=client.run, name="agent-sync-poller", daemon=True)
    thread.start()
    logger.info("Agent reverse poller started")
    return client

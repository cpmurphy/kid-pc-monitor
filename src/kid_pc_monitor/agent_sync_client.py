"""Agent-side reverse TCP client for the parent web panel."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import random
import socket
import ssl
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from kid_pc_monitor import agent_protocol, shared_secret
from kid_pc_monitor.network import get_local_ip
from kid_pc_monitor.pc_time_control import data_dir
from kid_pc_monitor.remote_control_server import handle_request

logger = logging.getLogger("AgentReverseClient")

DEFAULT_PANEL_PORT = 5000
DEFAULT_REVERSE_PORT = 9998
DISCOVERY_TIMEOUT_SEC = 0.5
CONNECT_TIMEOUT_SEC = 10
FRAME_TIMEOUT_SEC = 120
RECONNECT_MIN_SEC = 2
RECONNECT_MAX_SEC = 60
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


def _http_json(url: str, *, timeout: float) -> dict[str, Any]:
    req = UrlRequest(url, headers={"Accept": "application/json"}, method="GET")
    with urlopen(req, timeout=timeout) as response:  # noqa: S310 - LAN URL controlled by config/discovery.
        body = response.read().decode("utf-8")
    return json.loads(body)


def _discover_payload(base_url: str) -> dict[str, Any] | None:
    try:
        payload = _http_json(
            urljoin(base_url.rstrip("/") + "/", "agent/v1/discover"),
            timeout=DISCOVERY_TIMEOUT_SEC,
        )
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None
    if payload.get("service") != DISCOVERY_MARKER:
        return None
    return payload


def _is_panel_url(base_url: str) -> bool:
    return _discover_payload(base_url) is not None


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


def _reverse_endpoint(panel_url: str) -> tuple[str, int, bool]:
    """Return (host, reverse_port, use_tls) for the reverse TCP connection."""
    parsed = urlparse(panel_url)
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"Invalid panel URL: {panel_url}")
    payload = _discover_payload(panel_url) or {}
    reverse_port = payload.get("reverse_port", DEFAULT_REVERSE_PORT)
    try:
        port = int(reverse_port)
    except (TypeError, ValueError):
        port = DEFAULT_REVERSE_PORT
    use_tls = parsed.scheme == "https"
    return host, port, use_tls


def _open_reverse_socket(host: str, port: int, *, use_tls: bool) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SEC)
    raw.settimeout(FRAME_TIMEOUT_SEC)
    if not use_tls:
        return raw
    context = ssl.create_default_context()
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except ssl.SSLError:
        raw.close()
        # LAN panels often use a locally generated cert; fall back unverified.
        raw = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SEC)
        raw.settimeout(FRAME_TIMEOUT_SEC)
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        return insecure.wrap_socket(raw, server_hostname=host)


class AgentReverseClient:
    """Maintain an outbound native-protocol session to the parent panel."""

    def __init__(self, control: Any):
        self.control = control
        self.panel_url: str | None = None
        self.running = False
        self._sock: socket.socket | None = None
        self._logged_connect_failure = False

    def _secret(self) -> str | None:
        return shared_secret.load_shared_secret()

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _log_connect_failure(self, exc: BaseException) -> None:
        message = "Reverse connect failed (%s); rediscovering"
        if self._logged_connect_failure:
            logger.debug(message, exc)
            return
        logger.warning(message, exc)
        self._logged_connect_failure = True

    def _serve_connection(self, sock: socket.socket, secret: str) -> None:
        self._sock = sock
        while self.running:
            try:
                body = agent_protocol.read_frame(sock)
            except agent_protocol.ConnectionClosedBeforeFrame:
                logger.info("Panel closed reverse connection")
                return
            except agent_protocol.ProtocolError as exc:
                logger.warning("Reverse framing error: %s", exc)
                return
            except (TimeoutError, OSError) as exc:
                logger.info("Reverse connection idle/error: %s", exc)
                return
            response = handle_request(self.control, body, secret=secret)
            try:
                sock.sendall(agent_protocol.encode_frame(response))
            except OSError as exc:
                logger.warning("Reverse send failed: %s", exc)
                return

    def connect_once(self) -> float:
        """Discover/connect and serve until disconnect. Returns reconnect delay."""
        secret = self._secret()
        if not secret:
            logger.error("No shared secret configured; reverse TCP disabled")
            return 30.0

        if self.panel_url is None:
            self.panel_url = discover_panel_url()
            if self.panel_url is None:
                logger.debug("No Kid PC Monitor panel discovered on this LAN")
                return 30.0

        try:
            host, port, use_tls = _reverse_endpoint(self.panel_url)
            sock = _open_reverse_socket(host, port, use_tls=use_tls)
        except (OSError, ValueError, HTTPError, URLError, json.JSONDecodeError) as exc:
            self._log_connect_failure(exc)
            self.panel_url = None
            return min(RECONNECT_MAX_SEC, RECONNECT_MIN_SEC + random.uniform(0, 3))

        self._logged_connect_failure = False
        logger.info(
            "Connected reverse session to panel %s:%s%s",
            host,
            port,
            " (TLS)" if use_tls else "",
        )
        try:
            self._serve_connection(sock, secret)
        finally:
            self._close_socket()
        return min(RECONNECT_MAX_SEC, RECONNECT_MIN_SEC + random.uniform(0, 3))

    def run(self) -> None:
        self.running = True
        delay = RECONNECT_MIN_SEC
        while self.running:
            try:
                delay = self.connect_once()
            except Exception:
                logger.exception("Reverse TCP cycle failed")
                delay = 15.0
            if self.running:
                time.sleep(delay)

    def stop(self) -> None:
        self.running = False
        self._close_socket()


# Backwards-compatible aliases for older imports/tests.
AgentSyncClient = AgentReverseClient


def start_agent_reverse_client(control: Any) -> AgentReverseClient:
    client = AgentReverseClient(control)
    thread = threading.Thread(target=client.run, name="agent-reverse-client", daemon=True)
    thread.start()
    logger.info("Agent reverse TCP client started")
    return client


def start_agent_sync_poller(control: Any) -> AgentReverseClient:
    """Deprecated alias for :func:`start_agent_reverse_client`."""
    return start_agent_reverse_client(control)

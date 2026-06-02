"""Kid PC Monitor agent process: logging, TCP server, and entry point."""

from __future__ import annotations

import getpass
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any

from kid_pc_monitor import agent_protocol, request_dispatcher, shared_secret
from kid_pc_monitor.host_platform import HostPlatform, get_default_platform
from kid_pc_monitor.network import get_primary_ipv4
from kid_pc_monitor.pc_time_control import PCTimeControl, data_dir

log_file = data_dir / "pc_control.log"
AGENT_PORT = 9999

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


# Simple Remote Control Server
class RemoteControlServer:
    def __init__(self, port=9999, timeout=60):
        """
        Initialize the remote control server.

        Args:
            port (int): Port number to listen on (default: 9999)
            timeout (int): Socket timeout in seconds (default: 60)
        """
        self.port = port
        self.timeout = timeout
        self.pc_control = None
        self.running = False
        self.server_socket = None
        self.clients = {}
        self.client_id_counter = 0
        self.last_primary_ip = None
        self.listener_ready = threading.Event()
        self.logger = logging.getLogger("RemoteControlServer")
        # The shared secret authenticates every protocol v2 frame.  It is
        # loaded lazily so a freshly installed agent reflects a secret added
        # after the process started.
        self._shared_secret = None

    def get_shared_secret(self):
        """Return the configured shared secret, loading and caching it once."""
        if self._shared_secret is None:
            self._shared_secret = shared_secret.load_shared_secret()
        return self._shared_secret

    def get_primary_ip(self):
        """Return the primary IPv4 address, or None while networking is down."""
        return get_primary_ipv4()

    def close_sockets(self):
        """Close active client and listener sockets without changing run intent."""
        for client_id, client_info in list(self.clients.items()):
            try:
                client_info["socket"].close()
            except Exception as e:
                self.logger.error(f"Error closing client socket {client_id}: {e}")
            del self.clients[client_id]

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing server socket: {e}")
            self.server_socket = None

    def check_for_ip_change(self):
        """Return True when the primary IP changed and the listener should restart."""
        current_ip = self.get_primary_ip()
        if current_ip != self.last_primary_ip:
            self.logger.warning(
                "Primary IP changed from %s to %s; restarting TCP listener",
                self.last_primary_ip or "none",
                current_ip or "none",
            )
            print(
                f"[{datetime.now():%H:%M:%S}] Network address changed "
                f"({self.last_primary_ip or 'none'} -> {current_ip or 'none'}); "
                "restarting server"
            )
            self.last_primary_ip = current_ip
            if self.pc_control is not None:
                log_connectivity_diagnostics(self.pc_control.platform)
            return True
        return False

    def start_server(self, pc_control):
        """Start the remote control server and recover from network/socket changes."""
        self.pc_control = pc_control
        self.running = True
        restart_delay = 1

        while self.running:
            self.listener_ready.clear()
            try:
                self.last_primary_ip = self.get_primary_ip()
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.settimeout(5)  # Allow periodic health checks.
                self.server_socket.bind(("0.0.0.0", self.port))
                self.server_socket.listen(5)
                self.listener_ready.set()

                self.logger.info(
                    "Listening on 0.0.0.0:%s (primary IP: %s)",
                    self.port,
                    self.last_primary_ip or "unknown",
                )
                restart_delay = 1

                while self.running:
                    try:
                        client_socket, client_address = self.server_socket.accept()
                        client_socket.settimeout(self.timeout)

                        client_id = self.client_id_counter
                        self.client_id_counter += 1

                        self.logger.debug(
                            "Client connected from %s (id=%s)",
                            client_address[0],
                            client_id,
                        )

                        # Start a new thread for each client
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, client_address, client_id),
                            daemon=True,
                        )
                        self.clients[client_id] = {
                            "thread": client_thread,
                            "socket": client_socket,
                            "address": client_address,
                        }
                        client_thread.start()

                    except TimeoutError:
                        if self.check_for_ip_change():
                            break
                        continue
                    except OSError as e:
                        if self.running:
                            self.logger.warning(
                                "Accept failed; restarting listener: %s", e, exc_info=True
                            )
                        break
                    except Exception as e:
                        if self.running:
                            self.logger.error(
                                "Accept error; restarting listener: %s", e, exc_info=True
                            )
                        break

            except Exception as e:
                if self.running:
                    self.logger.error(
                        "Listener bind/start failed; retry in %ss: %s",
                        restart_delay,
                        e,
                        exc_info=True,
                    )
            finally:
                self.close_sockets()

            if self.running:
                time.sleep(restart_delay)
                restart_delay = min(restart_delay * 2, 30)

        self.logger.info("Server stopped")

    def handle_client(self, client_socket, client_address, client_id):
        """Handle communication with a connected client using protocol v2."""
        try:
            while self.running:
                try:
                    body = agent_protocol.read_frame(client_socket)
                except agent_protocol.ConnectionClosedBeforeFrame as e:
                    # A bare TCP probe (e.g. the panel's reachability check)
                    # connects and closes without sending a frame. Benign.
                    self.logger.debug("Client %s closed before sending a frame: %s", client_id, e)
                    break
                except agent_protocol.ProtocolError as e:
                    self.logger.warning("Client %s framing error: %s", client_id, e)
                    break
                self.logger.debug("Structured request from %s (ID: %s)", client_address, client_id)
                secret = self.get_shared_secret()
                if not secret:
                    self.logger.error(
                        "No shared secret configured; cannot authenticate "
                        "client %s. Re-run the installer to set one.",
                        client_id,
                    )
                    break
                response = handle_request(self.pc_control, body, secret=secret)
                try:
                    client_socket.sendall(agent_protocol.encode_frame(response))
                except OSError as e:
                    self.logger.warning("Client %s send error: %s", client_id, e)
                    break

        finally:
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            self.logger.debug("Client %s (ID: %s) disconnected", client_address, client_id)

    def stop_server(self):
        """Stop the server and clean up resources."""
        self.running = False
        self.close_sockets()

    def __del__(self):
        """Destructor to ensure proper cleanup."""
        self.stop_server()


# Main
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

"""TCP server for parent panel and CLI remote control of the kid agent."""

from __future__ import annotations

import logging
import socket
import threading
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

from kid_pc_monitor import agent_protocol, shared_secret
from kid_pc_monitor.network import get_primary_ipv4

if TYPE_CHECKING:
    from kid_pc_monitor.pc_time_control import PCTimeControl

DEFAULT_AGENT_PORT = 9999


class RemoteControlServer:
    def __init__(self, port: int = DEFAULT_AGENT_PORT, timeout: int = 60):
        """
        Initialize the remote control server.

        Args:
            port (int): Port number to listen on (default: 9999)
            timeout (int): Socket timeout in seconds (default: 60)
        """
        self.port = port
        self.timeout = timeout
        self.pc_control: PCTimeControl | None = None
        self.running = False
        self.server_socket = None
        self.clients: dict[int, dict[str, Any]] = {}
        self.client_id_counter = 0
        self.last_primary_ip: str | None = None
        self.listener_ready = threading.Event()
        self.logger = logging.getLogger("RemoteControlServer")
        # The shared secret authenticates every protocol v2 frame.  It is
        # loaded lazily so a freshly installed agent reflects a secret added
        # after the process started.
        self._shared_secret: str | None = None

    def get_shared_secret(self) -> str | None:
        """Return the configured shared secret, loading and caching it once."""
        if self._shared_secret is None:
            self._shared_secret = shared_secret.load_shared_secret()
        return self._shared_secret

    def get_primary_ip(self) -> str | None:
        """Return the primary IPv4 address, or None while networking is down."""
        return get_primary_ipv4()

    def close_sockets(self) -> None:
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

    def check_for_ip_change(self) -> bool:
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
                from kid_pc_monitor.pc_control import log_connectivity_diagnostics

                log_connectivity_diagnostics(self.pc_control.platform)
            return True
        return False

    def start_server(self, pc_control: PCTimeControl) -> None:
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

    def handle_client(
        self, client_socket: socket.socket, client_address: tuple, client_id: int
    ) -> None:
        """Handle communication with a connected client using protocol v2."""
        from kid_pc_monitor.pc_control import handle_request

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
                assert self.pc_control is not None
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

    def stop_server(self) -> None:
        """Stop the server and clean up resources."""
        self.running = False
        self.close_sockets()

    def __del__(self) -> None:
        """Destructor to ensure proper cleanup."""
        self.stop_server()

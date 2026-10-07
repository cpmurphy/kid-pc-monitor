"""Tests for the panel reverse TCP listener's own socket handling."""

from __future__ import annotations

import socket
import unittest
from typing import Any
from unittest import mock

from kid_pc_monitor import panel_reverse_server as reverse


class ReverseListenerSocketTests(unittest.TestCase):
    def test_failed_bind_closes_each_listener_socket(self) -> None:
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(blocker.close)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]

        server = reverse.PanelReverseServer(host="127.0.0.1", port=port)
        server.running = True
        created: list[socket.socket] = []
        real_socket = socket.socket
        attempts = 0

        def tracking_socket(*args: Any, **kwargs: Any) -> socket.socket:
            sock = real_socket(*args, **kwargs)
            created.append(sock)
            return sock

        def stop_after_retries(_seconds: float) -> None:
            nonlocal attempts
            attempts += 1
            if attempts >= 3:
                server.running = False

        with (
            mock.patch.object(reverse.socket, "socket", side_effect=tracking_socket),
            mock.patch.object(reverse.time, "sleep", side_effect=stop_after_retries),
            self.assertLogs(reverse.logger, level="ERROR"),
        ):
            server._serve()

        self.assertEqual(len(created), 3)
        self.assertTrue(all(sock.fileno() == -1 for sock in created))


if __name__ == "__main__":
    unittest.main()

"""Tests for remote_client reachability helpers."""

from __future__ import annotations

import socket
import threading
import unittest

from src.remote_client import is_pc_reachable, refresh_discovered_entry


class RemoteClientTests(unittest.TestCase):
    def test_is_pc_reachable_open_port(self) -> None:
        ready = threading.Event()
        port_holder: list[int] = []

        def serve() -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 0))
                server.listen(1)
                port_holder.append(server.getsockname()[1])
                ready.set()
                conn, _addr = server.accept()
                with conn:
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        ready.wait(timeout=2)
        port = port_holder[0]

        self.assertTrue(is_pc_reachable("127.0.0.1", port=port, timeout=1.0))
        thread.join(timeout=2)

    def test_is_pc_reachable_closed_port(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertFalse(is_pc_reachable("127.0.0.1", port=port, timeout=0.5))

    def test_refresh_discovered_entry_marks_offline(self) -> None:
        entry = {
            "hostname": "Test",
            "status": "online",
            "locked": True,
            "current_user": "kid",
            "usage_limit": 60,
        }
        refresh_discovered_entry("127.0.0.1", entry, port=1)
        self.assertFalse(entry["reachable"])
        self.assertEqual(entry["status"], "offline")
        self.assertFalse(entry["locked"])
        self.assertNotIn("current_user", entry)
        self.assertNotIn("usage_limit", entry)


if __name__ == "__main__":
    unittest.main()

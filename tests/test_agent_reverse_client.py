"""Tests for agent reverse TCP client reconnect logging."""

from __future__ import annotations

import logging
import unittest
from unittest import mock

from kid_pc_monitor import agent_sync_client as client


class AgentReverseConnectLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = client.AgentReverseClient(control=mock.Mock())

    def test_connect_failure_warning_only_once_until_success(self) -> None:
        with (
            mock.patch.object(self.client, "_secret", return_value="secret"),
            mock.patch.object(client, "discover_panel_url", return_value="http://127.0.0.1:5000"),
            mock.patch.object(
                client,
                "_reverse_endpoint",
                return_value=("127.0.0.1", 9998, False),
            ),
            mock.patch.object(
                client,
                "_open_reverse_socket",
                side_effect=OSError("refused"),
            ),
            self.assertLogs(client.logger, level="DEBUG") as captured,
        ):
            self.client.panel_url = "http://127.0.0.1:5000"
            self.client.connect_once()
            self.client.panel_url = "http://127.0.0.1:5000"
            self.client.connect_once()

        warnings = [r for r in captured.records if r.levelno == logging.WARNING]
        debugs = [r for r in captured.records if r.levelno == logging.DEBUG]
        self.assertEqual(len(warnings), 1)
        self.assertIn("Reverse connect failed", warnings[0].getMessage())
        self.assertTrue(any("Reverse connect failed" in r.getMessage() for r in debugs))

    def test_successful_connect_resets_failure_logging(self) -> None:
        sock = mock.Mock()
        with (
            mock.patch.object(self.client, "_secret", return_value="secret"),
            mock.patch.object(
                client,
                "_reverse_endpoint",
                return_value=("127.0.0.1", 9998, False),
            ),
            mock.patch.object(client, "_open_reverse_socket", return_value=sock),
            mock.patch.object(self.client, "_serve_connection"),
            mock.patch.object(self.client, "_close_socket"),
        ):
            self.client._logged_connect_failure = True
            self.client.panel_url = "http://127.0.0.1:5000"
            self.client.connect_once()

        self.assertFalse(self.client._logged_connect_failure)


if __name__ == "__main__":
    unittest.main()

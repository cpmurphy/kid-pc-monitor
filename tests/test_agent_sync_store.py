"""Tests for reverse agent polling persistence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor import agent_sync_store as store
from kid_pc_monitor import panel_db


class AgentSyncStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patch = mock.patch.object(panel_db, "_db_path_override", self.db_path)
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_record_agent_poll_and_lookup_by_ip(self) -> None:
        store.record_agent_poll(
            "KidPC",
            "192.168.1.10",
            {"hostname": "KidPC", "status": "UNLOCKED", "reachable": True},
        )

        agent = store.recent_agent_for_ip("192.168.1.10")

        assert agent is not None
        self.assertEqual(agent["hostname"], "KidPC")
        self.assertEqual(agent["ip"], "192.168.1.10")
        self.assertEqual(agent["status"], "UNLOCKED")

    def test_command_lifecycle(self) -> None:
        command_id = store.enqueue_command(
            hostname="KidPC",
            action_name="lock",
            request_fields={"action": "lock", "var": None, "val": None, "tail": None},
        )

        queued = store.command_status(command_id)
        assert queued is not None
        self.assertTrue(queued["pending"])
        self.assertEqual(queued["response"], "Command is waiting for the agent to poll.")

        commands = store.take_pending_commands("KidPC", secret="secret")
        self.assertEqual(commands[0]["id"], command_id)
        req = proto.parse_request(commands[0]["request"], secret="secret", hostname="KidPC")
        self.assertEqual(req.action, "lock")
        self.assertEqual(store.take_pending_commands("KidPC", secret="secret"), [])

        delivered = store.command_status(command_id)
        assert delivered is not None
        self.assertTrue(delivered["pending"])
        self.assertEqual(delivered["response"], "Command delivered; waiting for result.")

        recorded = store.record_command_result(
            command_id, "response", hostname="KidPC", error_text="boom"
        )
        self.assertTrue(recorded)
        failed = store.command_status(command_id)
        assert failed is not None
        self.assertFalse(failed["success"])
        self.assertEqual(failed["response"], "boom")

    def test_command_result_requires_matching_hostname(self) -> None:
        command_id = store.enqueue_command(
            hostname="KidPC",
            action_name="lock",
            request_fields={"action": "lock", "var": None, "val": None, "tail": None},
        )

        recorded = store.record_command_result(
            command_id, "response", hostname="OtherPC", error_text="boom"
        )

        self.assertFalse(recorded)
        status = store.command_status(command_id)
        assert status is not None
        self.assertTrue(status["pending"])


if __name__ == "__main__":
    unittest.main()

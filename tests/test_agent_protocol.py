"""Tests for the structured agent protocol (agent_protocol.py)."""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from datetime import time as dtime
from pathlib import Path

from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.agent_protocol import Node, ProtocolError
from kid_pc_monitor.pc_control import PCTimeControl, RemoteControlServer

from test_pc_control import FakeHostPlatform


class KdlSerializationTests(unittest.TestCase):
    def test_scalar_round_trip(self) -> None:
        nodes = [
            Node("v", [1]),
            Node("id", ["b9e7c0"]),
            Node("status", ["ok"]),
            Node("result", [120]),
        ]
        body = proto.serialize(nodes)
        self.assertEqual(body, "v 1\nid b9e7c0\nstatus ok\nresult 120")
        reparsed = proto.parse(body)
        self.assertEqual([n.name for n in reparsed], ["v", "id", "status", "result"])
        self.assertEqual(reparsed[0].arg, 1)
        self.assertEqual(reparsed[3].arg, 120)

    def test_bool_and_null(self) -> None:
        body = proto.serialize([Node("a", [True]), Node("b", [False]), Node("c", [None])])
        self.assertEqual(body, "a true\nb false\nc null")
        parsed = {n.name: n.arg for n in proto.parse(body)}
        self.assertIs(parsed["a"], True)
        self.assertIs(parsed["b"], False)
        self.assertIsNone(parsed["c"])

    def test_strings_quoted_when_needed(self) -> None:
        self.assertEqual(proto.format_value("LOCKED"), "LOCKED")
        # Leading digit would be ambiguous with a number, so times are quoted.
        self.assertEqual(proto.format_value("21:00"), '"21:00"')
        self.assertEqual(proto.format_value("Tommy's Laptop"), '"Tommy\'s Laptop"')
        self.assertEqual(proto.format_value("true"), '"true"')  # keyword must quote
        self.assertEqual(proto.format_value(""), '""')

    def test_escape_round_trip(self) -> None:
        original = 'line1\nline2\t"quoted"\\end'
        body = proto.serialize([Node("msg", [original])])
        self.assertEqual(proto.parse(body)[0].arg, original)

    def test_block_round_trip(self) -> None:
        block = Node("error", children=[Node("code", ["invalid_value"]), Node("message", ["nope"])])
        body = proto.serialize([Node("status", ["failure"]), block])
        parsed = {n.name: n for n in proto.parse(body)}
        self.assertEqual(parsed["error"].child_map(), {"code": "invalid_value", "message": "nope"})

    def test_parse_rejects_unbalanced_brace(self) -> None:
        with self.assertRaises(ProtocolError):
            proto.parse("foo {\n  bar 1")
        with self.assertRaises(ProtocolError):
            proto.parse("bar 1\n}")


class FramingTests(unittest.TestCase):
    def test_encode_length_matches_body_bytes(self) -> None:
        frame = proto.encode_frame("v 1")
        self.assertEqual(frame, b"3\nv 1")

    def test_encode_counts_utf8_bytes(self) -> None:
        frame = proto.encode_frame("é")  # 2 bytes in UTF-8
        self.assertTrue(frame.startswith(b"2\n"))

    def test_inspect_complete_with_leftover(self) -> None:
        buffer = proto.encode_frame("v 1") + b"extra"
        status, body, rest = proto.inspect_frame(buffer)
        self.assertEqual(status, proto.COMPLETE)
        self.assertEqual(body, "v 1")
        self.assertEqual(rest, b"extra")

    def test_inspect_incomplete(self) -> None:
        status, body, _rest = proto.inspect_frame(b"10\nshort")
        self.assertEqual(status, proto.INCOMPLETE)
        self.assertIsNone(body)

    def test_inspect_incomplete_bare_digits(self) -> None:
        status, _body, _rest = proto.inspect_frame(b"35")
        self.assertEqual(status, proto.INCOMPLETE)

    def test_inspect_non_numeric_is_not_frame(self) -> None:
        status, _body, _rest = proto.inspect_frame(b"GET_STATUS")
        self.assertEqual(status, proto.NOT_FRAME)

    def test_inspect_rejects_oversized(self) -> None:
        with self.assertRaises(ProtocolError):
            proto.inspect_frame(f"{proto.MAX_FRAME_BYTES + 1}\nx".encode())

    def test_read_frame_across_chunks(self) -> None:
        frame = proto.encode_frame("v 1\nstatus ok")

        class ChunkSocket:
            def __init__(self, data: bytes) -> None:
                self.data = data
                self.pos = 0

            def recv(self, n: int) -> bytes:
                chunk = self.data[self.pos : self.pos + 3]  # tiny reads
                self.pos += len(chunk)
                return chunk

        self.assertEqual(proto.read_frame(ChunkSocket(frame)), "v 1\nstatus ok")


class RequestValidationTests(unittest.TestCase):
    def test_build_and_parse_round_trip(self) -> None:
        body = proto.build_request("set", var="daily_limit", val=120, req_id="abc123")
        req = proto.parse_request(body)
        self.assertEqual((req.action, req.var, req.val, req.id), ("set", "daily_limit", 120, "abc123"))

    def test_missing_version(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request("action lock")
        self.assertEqual(ctx.exception.code, proto.INVALID_REQUEST)

    def test_unsupported_version(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request("v 2\naction lock")
        self.assertEqual(ctx.exception.code, proto.UNSUPPORTED_VERSION)

    def test_unknown_action(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request("v 1\naction explode")
        self.assertEqual(ctx.exception.code, proto.UNKNOWN_ACTION)

    def test_unknown_variable(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request("v 1\naction get\nvar nonsense")
        self.assertEqual(ctx.exception.code, proto.UNKNOWN_VARIABLE)

    def test_set_requires_value(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request("v 1\naction set\nvar daily_limit")
        self.assertEqual(ctx.exception.code, proto.INVALID_REQUEST)

    def test_error_echoes_request_id(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request("v 1\nid xyz\naction explode")
        self.assertEqual(ctx.exception.req_id, "xyz")


class ResponseBuildingTests(unittest.TestCase):
    def test_ok_response(self) -> None:
        resp = proto.parse_response(proto.ok_response("abc", 120))
        self.assertTrue(resp.ok)
        self.assertEqual(resp.result, 120)
        self.assertEqual(resp.id, "abc")

    def test_error_response(self) -> None:
        resp = proto.parse_response(proto.error_response("abc", proto.INVALID_VALUE, "bad"))
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_code, proto.INVALID_VALUE)
        self.assertEqual(resp.error_message, "bad")
        self.assertIn("invalid_value", resp.text)

    def test_capabilities_response(self) -> None:
        nodes = {n.name: n for n in proto.parse(proto.capabilities_response("abc"))}
        actions = nodes["actions"].child_map()
        self.assertIn("get", actions)
        self.assertIn("extend", actions)
        self.assertIn("daily_limit", nodes["values"].child_map())


class DispatchTests(unittest.TestCase):
    def _control(self, tmp: str, **kwargs) -> PCTimeControl:
        return PCTimeControl(
            platform=FakeHostPlatform(**kwargs),
            data_directory=Path(tmp),
            start_background_threads=False,
        )

    def _handle(self, control: PCTimeControl, **req_kwargs) -> proto.Response:
        body = proto.build_request(req_id="r1", **req_kwargs)
        return proto.parse_response(proto.handle_request(control, body))

    def test_get_settings_returns_all_variables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp, hostname="kid-pc")
            control.set_daily_allowance(90)
            control.set_bed_time(21, 0)
            resp = self._handle(control, action="get", var="settings")
            self.assertTrue(resp.ok)
            self.assertEqual(resp.settings["name"], "kid-pc")
            self.assertEqual(resp.settings["daily_limit"], 90)
            self.assertEqual(resp.settings["bed_time"], "21:00")
            self.assertEqual(resp.settings["status"], "UNLOCKED")
            self.assertIs(resp.settings["manual_lock"], False)

    def test_get_single_variable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.set_daily_allowance(45)
            resp = self._handle(control, action="get", var="daily_limit")
            self.assertEqual(resp.result, 45)

    def test_set_daily_limit_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="daily_limit", val=120)
            self.assertTrue(resp.ok)
            self.assertEqual(control.daily.allowance, 120)

    def test_set_daily_limit_out_of_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="daily_limit", val=99999)
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_VALUE)
            self.assertIsNone(control.daily.allowance)

    def test_set_bed_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="bed_time", val="21:30")
            self.assertTrue(resp.ok)
            self.assertEqual(control.daily.bed_time, dtime(21, 30))

    def test_set_bad_time_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="wake_time", val="25:00")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_VALUE)

    def test_set_read_only_variable_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="status", val="LOCKED")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.FORBIDDEN)

    def test_set_manual_lock_locks_pc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="set", var="manual_lock", val=True)
            self.assertTrue(resp.ok)
            self.assertTrue(control.runtime.manual_lock_active)
            self.assertEqual(control.platform.lock_calls, 1)

    def test_lock_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="lock")
            self.assertEqual(resp.result, "locked")
            self.assertTrue(control.runtime.manual_lock_active)

    def test_unlock_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.runtime.manual_lock_active = True
            resp = self._handle(control, action="unlock")
            self.assertEqual(resp.result, "unlocked")
            self.assertFalse(control.runtime.manual_lock_active)

    def test_clear_daily_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.set_daily_allowance(60)
            resp = self._handle(control, action="clear", var="daily_limit")
            self.assertTrue(resp.ok)
            self.assertIsNone(control.daily.allowance)

    def test_clear_read_only_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="clear", var="status")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.FORBIDDEN)

    def test_extend_adds_to_extension_without_resetting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            control.runtime.cumulative_extension_seconds = 600
            control.runtime.accumulated_seconds = 300.0
            resp = self._handle(control, action="extend", val=15)
            self.assertTrue(resp.ok)
            # Extension grows; usage already accumulated is left untouched.
            self.assertEqual(control.runtime.cumulative_extension_seconds, 600 + 15 * 60)
            self.assertEqual(control.runtime.accumulated_seconds, 300.0)

    def test_extend_requires_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="extend")
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_REQUEST)

    def test_message_shows_popup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = self._handle(control, action="message", val="dinner time")
            self.assertTrue(resp.ok)
            self.assertIn(("PC Time Control", "dinner time"), control.platform.messages)

    def test_shutdown_default_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            self.assertTrue(self._handle(control, action="shutdown").ok)
            self.assertTrue(self._handle(control, action="shutdown", val=30).ok)
            self.assertEqual(control.platform.shutdown_calls, [60, 30])

    def test_list_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            body = proto.handle_request(control, proto.build_request("list_capabilities"))
            nodes = {n.name: n for n in proto.parse(body)}
            self.assertIn("actions", nodes)
            self.assertIn("values", nodes)

    def test_malformed_request_yields_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self._control(tmp)
            resp = proto.parse_response(proto.handle_request(control, "this is not valid"))
            self.assertFalse(resp.ok)
            self.assertEqual(resp.error_code, proto.INVALID_REQUEST)


class ServerIntegrationTests(unittest.TestCase):
    """Drive RemoteControlServer.handle_client over a socket pair."""

    def _serve(self, control: PCTimeControl):
        server = RemoteControlServer()
        server.pc_control = control
        server.running = True
        client_end, server_end = socket.socketpair()
        thread = threading.Thread(
            target=server.handle_client, args=(server_end, ("test", 0), 0), daemon=True
        )
        thread.start()
        return client_end, thread

    def test_structured_request_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = PCTimeControl(
                platform=FakeHostPlatform(hostname="kid-pc"),
                data_directory=Path(tmp),
                start_background_threads=False,
            )
            client_end, thread = self._serve(control)
            try:
                client_end.sendall(proto.encode_frame(proto.build_request("get", var="name")))
                resp = proto.parse_response(proto.read_frame(client_end))
                self.assertEqual(resp.result, "kid-pc")

                client_end.sendall(
                    proto.encode_frame(proto.build_request("set", var="daily_limit", val=75))
                )
                resp = proto.parse_response(proto.read_frame(client_end))
                self.assertTrue(resp.ok)
                self.assertEqual(control.daily.allowance, 75)
            finally:
                client_end.close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

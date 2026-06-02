"""Tests for the structured agent protocol (agent_protocol.py), protocol v2."""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from kid_pc_monitor import agent_auth
from kid_pc_monitor import agent_protocol as proto
from kid_pc_monitor.agent_protocol import Node, ProtocolError
from kid_pc_monitor.pc_control import PCTimeControl, RemoteControlServer
from test_pc_control import FakeHostPlatform

SECRET = "test-shared-secret"
HOSTNAME = "kid-pc"


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
    def _parse(self, body: str, *, hostname: str = HOSTNAME, now=None) -> proto.Request:
        return proto.parse_request(body, secret=SECRET, hostname=hostname, now=now)

    def test_build_and_parse_round_trip(self) -> None:
        body = proto.build_request(
            "set", secret=SECRET, var="daily_limit", val=120, req_id="abc123", name=HOSTNAME
        )
        req = self._parse(body)
        self.assertEqual(
            (req.action, req.var, req.val, req.id), ("set", "daily_limit", 120, "abc123")
        )
        self.assertEqual(req.name, HOSTNAME)

    def test_missing_version(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            self._parse("action lock")
        self.assertEqual(ctx.exception.code, proto.INVALID_REQUEST)

    def test_unsupported_version_v1(self) -> None:
        # v1 frames are no longer accepted now that v2 security is mandatory.
        with self.assertRaises(ProtocolError) as ctx:
            self._parse("v 1\naction lock")
        self.assertEqual(ctx.exception.code, proto.UNSUPPORTED_VERSION)

    def test_unknown_action(self) -> None:
        body = proto.build_request("explode", secret=SECRET, name=HOSTNAME)
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.code, proto.UNKNOWN_ACTION)

    def test_unknown_variable(self) -> None:
        body = proto.build_request("get", secret=SECRET, var="nonsense", name=HOSTNAME)
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.code, proto.UNKNOWN_VARIABLE)

    def test_set_requires_value(self) -> None:
        body = proto.build_request("set", secret=SECRET, var="daily_limit", name=HOSTNAME)
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.code, proto.INVALID_REQUEST)

    def test_error_echoes_request_id(self) -> None:
        body = proto.build_request("explode", secret=SECRET, req_id="xyz", name=HOSTNAME)
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.req_id, "xyz")

    def test_read_only_action_allowed_without_name(self) -> None:
        body = proto.build_request("get", secret=SECRET, var="name")
        req = self._parse(body)
        self.assertEqual(req.action, "get")
        self.assertIsNone(req.name)


class AuthenticationTests(unittest.TestCase):
    """Signature, timestamp, nonce, and cross-PC binding on requests."""

    def _parse(self, body: str, *, hostname: str = HOSTNAME, now=None) -> proto.Request:
        return proto.parse_request(body, secret=SECRET, hostname=hostname, now=now)

    def test_missing_auth_block_rejected(self) -> None:
        # A v2 frame with no auth block at all.
        body = 'v 3\nname kid-pc\ntimestamp 1710000000\nnonce "%s"\naction lock' % ("a" * 32)
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_REQUIRED)

    def test_tampered_request_rejected(self) -> None:
        body = proto.build_request(
            "set",
            secret=SECRET,
            var="daily_limit",
            val=120,
            name=HOSTNAME,
            timestamp=1710000000,
            nonce="a" * 32,
        )
        tampered = body.replace("val 120", "val 999")
        self.assertIn("val 999", tampered)
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(tampered, now=1710000000)
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_FAILED)

    def test_wrong_secret_rejected(self) -> None:
        body = proto.build_request("get", secret="some-other-secret", var="name")
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_FAILED)

    def test_stale_timestamp_rejected(self) -> None:
        body = proto.build_request("get", secret=SECRET, var="name", timestamp=1000, nonce="b" * 32)
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body, now=1000 + agent_auth.TIMESTAMP_WINDOW_SECONDS + 5)
        self.assertEqual(ctx.exception.code, proto.STALE_TIMESTAMP)

    def test_fresh_timestamp_within_window_accepted(self) -> None:
        body = proto.build_request("get", secret=SECRET, var="name", timestamp=1000, nonce="c" * 32)
        req = self._parse(body, now=1000 + agent_auth.TIMESTAMP_WINDOW_SECONDS - 1)
        self.assertEqual(req.action, "get")

    def test_write_without_name_requires_authentication(self) -> None:
        body = proto.build_request("lock", secret=SECRET)  # no name
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_REQUIRED)

    def test_name_mismatch_rejected(self) -> None:
        body = proto.build_request("unlock", secret=SECRET, name="some-other-pc")
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body, hostname=HOSTNAME)
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_FAILED)

    def test_cross_pc_replay_rejected(self) -> None:
        # An unlock genuinely issued for bedroom-pc, captured and replayed at
        # living-room-pc. The signed ``name`` field binds the frame to
        # bedroom-pc, so living-room-pc rejects the mismatch.
        captured = proto.build_request("unlock", secret=SECRET, name="bedroom-pc")
        with self.assertRaises(ProtocolError) as ctx:
            proto.parse_request(captured, secret=SECRET, hostname="living-room-pc")
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_FAILED)

    def test_short_nonce_rejected(self) -> None:
        body = proto.build_request("get", secret=SECRET, var="name", nonce="abc")
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body)
        self.assertEqual(ctx.exception.code, proto.INVALID_REQUEST)


class ResponseBuildingTests(unittest.TestCase):
    def _parse(self, body: str, **kwargs) -> proto.Response:
        return proto.parse_response(body, secret=SECRET, **kwargs)

    def test_ok_response_round_trip(self) -> None:
        body = proto.sign_response(
            proto.ok_content(120), secret=SECRET, hostname=HOSTNAME, req_id="abc"
        )
        resp = self._parse(body, expected_name=HOSTNAME)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.result, 120)
        self.assertEqual(resp.id, "abc")
        self.assertEqual(resp.name, HOSTNAME)

    def test_error_response_round_trip(self) -> None:
        body = proto.sign_response(
            proto.error_content(proto.INVALID_VALUE, "bad"),
            secret=SECRET,
            hostname=HOSTNAME,
            req_id="abc",
        )
        resp = self._parse(body)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.error_code, proto.INVALID_VALUE)
        self.assertEqual(resp.error_message, "bad")
        self.assertIn("invalid_value", resp.text)

    def test_capabilities_response(self) -> None:
        body = proto.sign_response(proto.capabilities_content(), secret=SECRET, hostname=HOSTNAME)
        nodes = {n.name: n for n in proto.parse(body)}
        actions = nodes["actions"].child_map()
        self.assertIn("get", actions)
        self.assertIn("extend", actions)
        self.assertIn("daily_limit", nodes["values"].child_map())

    def test_tampered_response_rejected(self) -> None:
        body = proto.sign_response(proto.ok_content("unlocked"), secret=SECRET, hostname=HOSTNAME)
        tampered = body.replace("unlocked", "locked!!")
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(tampered)
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_FAILED)

    def test_response_from_unexpected_agent_rejected(self) -> None:
        body = proto.sign_response(
            proto.ok_content("unlocked"), secret=SECRET, hostname="living-room-pc"
        )
        with self.assertRaises(ProtocolError) as ctx:
            self._parse(body, expected_name="bedroom-pc")
        self.assertEqual(ctx.exception.code, proto.AUTHENTICATION_FAILED)


class ServerIntegrationTests(unittest.TestCase):
    """Drive RemoteControlServer.handle_client over a socket pair."""

    def _serve(self, control: PCTimeControl):
        server = RemoteControlServer()
        server.pc_control = control
        server.running = True
        server._shared_secret = SECRET
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
                # Discovery: unnamed read learns and authenticates the hostname.
                client_end.sendall(
                    proto.encode_frame(proto.build_request("get", secret=SECRET, var="name"))
                )
                resp = proto.parse_response(proto.read_frame(client_end), secret=SECRET)
                self.assertEqual(resp.result, "kid-pc")
                self.assertEqual(resp.name, "kid-pc")

                # A named write, signed with the per-agent key.
                client_end.sendall(
                    proto.encode_frame(
                        proto.build_request(
                            "set", secret=SECRET, var="daily_limit", val=75, name="kid-pc"
                        )
                    )
                )
                resp = proto.parse_response(
                    proto.read_frame(client_end), secret=SECRET, expected_name="kid-pc"
                )
                self.assertTrue(resp.ok)
                self.assertEqual(control.daily.allowance, 75)
            finally:
                client_end.close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

"""Generate the golden protocol vectors shared by the Python and Go implementations.

The vectors are a snapshot of what :mod:`kid_pc_monitor.agent_protocol` does
for a hand-written list of inputs.  Both languages consume the resulting JSON
(``testdata/protocol/vectors.json``): ``tests/test_protocol_vectors.py`` checks
that the file still matches Python, and ``go/protocol`` checks that Go agrees.

Usage (from the repo root)::

    python tests/protocol_vectors_gen.py          # rewrite the vectors file
    python tests/protocol_vectors_gen.py --check  # exit 1 if the file is stale

If you change protocol behavior on purpose, regenerate the file; the Go tests
will then fail until the Go package is brought in line.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kid_pc_monitor import agent_auth  # noqa: E402
from kid_pc_monitor import agent_protocol as proto  # noqa: E402
from kid_pc_monitor.agent_protocol import Node, ProtocolError  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "protocol" / "vectors.json"

SECRET = "test-shared-secret"
SECRET_UNICODE = "pässwörd 🔑 with spaces"
HOSTNAME = "kid-pc"
NOW = 1_710_000_000
NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
NONCE_2 = "0123456789abcdef0123456789abcdef"


# ---------------------------------------------------------------------------
# JSON encoding helpers
# ---------------------------------------------------------------------------
def node_json(node: Node) -> dict[str, Any]:
    out: dict[str, Any] = {"name": node.name, "args": list(node.args)}
    if node.children:
        out["children"] = [node_json(child) for child in node.children]
    return out


def nodes_json(nodes: list[Node]) -> list[dict[str, Any]]:
    return [node_json(node) for node in nodes]


def node_from_json(data: dict[str, Any]) -> Node:
    return Node(
        data["name"],
        list(data.get("args", [])),
        [node_from_json(child) for child in data.get("children", [])],
    )


def error_json(exc: ProtocolError) -> dict[str, Any]:
    return {"code": exc.code, "req_id": exc.req_id}


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------
FORMAT_VALUE_INPUTS: list[Any] = [
    "LOCKED",
    "21:00",
    "Tommy's Laptop",
    "true",
    "false",
    "null",
    "True",
    "",
    "hello\n",
    "a\nb",
    'a"b',
    "back\\slash",
    "tab\there",
    "cr\rhere",
    "ünï 🔑",
    "x y",
    "_x",
    "a.b:c+d-e",
    "a/b",
    "123",
    "-",
    "1e5",
    "a;b",
    "a{b",
    "a\x00b",
    0,
    -5,
    120,
    2**53,
    True,
    False,
    None,
]


def format_value_cases() -> list[dict[str, Any]]:
    return [{"value": value, "text": proto.format_value(value)} for value in FORMAT_VALUE_INPUTS]


SERIALIZE_CASES: list[tuple[str, list[Node]]] = [
    ("empty", []),
    (
        "scalars",
        [Node("v", [3]), Node("id", ["b9e7c0"]), Node("status", ["ok"]), Node("result", [120])],
    ),
    ("bool_null", [Node("a", [True]), Node("b", [False]), Node("c", [None])]),
    ("no_args", [Node("lines")]),
    ("many_args", [Node("lines", ["a b", "c", 3, True, None])]),
    (
        "block",
        [
            Node("status", ["failure"]),
            Node(
                "error",
                children=[Node("code", ["invalid_value"]), Node("message", ["nope: 1..1440"])],
            ),
        ],
    ),
    (
        "nested_block",
        [Node("a", children=[Node("b", [1], children=[Node("c", ["x y"])]), Node("d")])],
    ),
    ("block_with_args", [Node("logs", ["x"], children=[Node("path", ["C:\\a\\b.log"])])]),
    ("multiline_string", [Node("message", ['line1\nline2\ttabbed "quoted" \\ end'])]),
    ("unicode", [Node("message", ["ünï 🔑 日本語"])]),
]


def serialize_cases() -> list[dict[str, Any]]:
    return [
        {"name": name, "nodes": nodes_json(nodes), "text": proto.serialize(nodes)}
        for name, nodes in SERIALIZE_CASES
    ]


PARSE_TEXTS: list[tuple[str, str]] = [
    ("empty", ""),
    ("blank_lines", "\n\n  \n"),
    ("scalars", "v 3\nid b9e7c0\nstatus ok\nresult 120"),
    ("trailing_newline", "a 1\n"),
    ("crlf", "a 1\r\nb 2\r\n"),
    ("semicolons", "a 1; b 2;c 3"),
    ("keywords", "a true\nb false\nc null"),
    ("quoted_keywords_are_strings", 'a "true"\nb "null"\nc "123"'),
    ("numbers", "a 0\nb -7\nc +5\nd 007\ne 1_000"),
    ("not_numbers", "a 1.5\nb 0x10\nc 1e5\nd 12abc\ne -"),
    ("multiple_args", 'lines "a b" c 3 true null'),
    ("string_escapes", r'a "q\"uote\\ \n \t \r \/ end"'),
    ("unicode_escape", r'a "\u{41}\u{1F600}\u{e9}"'),
    ("raw_newline_in_string", 'a "line1\nline2"'),
    ("adjacent_string_and_word", 'a "x"y'),
    ("block", 'error {\n  code invalid_value\n  message "nope"\n}'),
    ("empty_block", "a {}\nb { }"),
    ("nested_block", "a {\n  b {\n    c 1\n  }\n  d\n}"),
    ("node_after_close_on_same_line", "a { b 1 } c 2"),
    ("block_with_args", "logs x {\n  path y\n}"),
    ("quoted_node_name", '"my node" 1'),
    ("bare_with_punct", "a b.c:d+e-f_g"),
    ("unterminated_string", 'a "oops'),
    ("unterminated_escape", 'a "oops\\'),
    ("bad_escape", r'a "\x41"'),
    ("bad_unicode_escape", r'a "\u{zz}"'),
    ("unterminated_unicode_escape", r'a "\u{41"'),
    ("unicode_escape_out_of_range", r'a "\u{110000}"'),
    ("unicode_escape_without_brace", r'a "\u0041"'),
    ("stray_close", "a 1\n}"),
    ("stray_open", "{ a 1 }"),
    ("missing_close", "foo {\n  bar 1"),
    ("keyword_node_name", "true 1"),
    ("numeric_node_name", "5 1"),
    ("null_node_name", "null"),
]


def _nested(levels: int) -> str:
    return "a {" * levels + "}" * levels


def parse_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    texts = [
        *PARSE_TEXTS,
        ("nesting_at_limit", _nested(proto.MAX_NESTING_DEPTH)),
        ("nesting_over_limit", _nested(proto.MAX_NESTING_DEPTH + 1)),
        ("nesting_hostile", "a {" * 5000),
    ]
    for name, text in texts:
        case: dict[str, Any] = {"name": name, "text": text}
        try:
            case["nodes"] = nodes_json(proto.parse(text))
        except ProtocolError as exc:
            case["error"] = exc.code
        cases.append(case)
    return cases


def frame_encode_cases() -> list[dict[str, Any]]:
    bodies = ["", "v 3", "multi\nline\nbody", "ünï 🔑", "x" * 1000]
    return [
        {"body": body, "frame_hex": proto.encode_frame(body).hex(), "length": len(body.encode())}
        for body in bodies
    ]


FRAME_INSPECT_INPUTS: list[tuple[str, bytes]] = [
    ("complete_exact", b"5\nhello"),
    ("complete_with_rest", b"5\nhelloextra"),
    ("complete_two_frames", b"2\nab3\ncde"),
    ("complete_empty_body", b"0\n"),
    ("complete_leading_zero", b"05\nhello"),
    ("complete_multibyte", "3\nüa".encode()),
    ("incomplete_body", b"10\nhello"),
    ("incomplete_no_body", b"5\n"),
    ("incomplete_digits_only", b"12"),
    ("incomplete_at_max", b"65536\nabc"),
    ("not_frame_empty", b""),
    ("not_frame_newline", b"\n"),
    ("not_frame_text", b"abc\nxyz"),
    ("not_frame_text_no_newline", b"abc"),
    ("not_frame_negative", b"-1\nab"),
    ("not_frame_space", b" 5\nhello"),
    ("not_frame_plus", b"+5\nhello"),
    ("not_frame_mixed", b"5a\nhello"),
    ("too_large", b"65537\nabc"),
    ("too_large_no_body", b"999999\n"),
]


def frame_inspect_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for name, data in FRAME_INSPECT_INPUTS:
        case: dict[str, Any] = {"name": name, "input_hex": data.hex()}
        try:
            status, body, rest = proto.inspect_frame(data)
        except ProtocolError as exc:
            case["error"] = exc.code
        else:
            case["status"] = status
            case["body"] = body
            case["rest_hex"] = rest.hex()
        cases.append(case)
    return cases


SIGNATURE_INPUTS: list[tuple[str, str, str]] = [
    ("simple", SECRET, "v 3\nname kid-pc\ntimestamp 1710000000"),
    ("empty_canonical", SECRET, ""),
    ("unicode_secret", SECRET_UNICODE, "v 3\naction get\nvar settings"),
    ("unicode_canonical", SECRET, 'v 3\nval "ünï 🔑"'),
    ("empty_secret", "", "v 3"),
    ("long_secret", "k" * 200, "v 3\nval 1"),
]


def signature_cases() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "secret": secret,
            "canonical": canonical,
            "signature": agent_auth.compute_signature(agent_auth.derive_key(secret), canonical),
        }
        for name, secret, canonical in SIGNATURE_INPUTS
    ]


NONCE_INPUTS: list[str] = [
    NONCE,
    "0" * 32,
    "F" * 32,
    "a" * 31,
    "a" * 64,
    "",
    "g" * 32,
    "a" * 31 + "z",
    "a" * 31 + " ",
    "0x" + "a" * 30,
    "a" * 16 + "_" + "a" * 15,
    " " + "a" * 31,
]


def nonce_cases() -> list[dict[str, Any]]:
    return [{"nonce": nonce, "valid": agent_auth.is_valid_nonce(nonce)} for nonce in NONCE_INPUTS]


WINDOW_INPUTS: list[tuple[int, int]] = [
    (NOW, NOW),
    (NOW - 60, NOW),
    (NOW + 60, NOW),
    (NOW - 61, NOW),
    (NOW + 61, NOW),
    (0, NOW),
    (-5, 10),
]


def window_cases() -> list[dict[str, Any]]:
    return [
        {"timestamp": ts, "now": now, "in_window": agent_auth.timestamp_in_window(ts, now=now)}
        for ts, now in WINDOW_INPUTS
    ]


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
def build_request_kwargs() -> list[tuple[str, dict[str, Any]]]:
    base: dict[str, Any] = {"secret": SECRET, "timestamp": NOW, "nonce": NONCE}
    return [
        ("get_settings_discovery", {**base, "action": "get", "var": "settings", "req_id": "r1"}),
        ("get_name_no_id", {**base, "action": "get", "var": "name"}),
        ("get_named", {**base, "action": "get", "var": "status", "name": HOSTNAME}),
        ("list_capabilities", {**base, "action": "list_capabilities", "req_id": "caps"}),
        ("lock", {**base, "action": "lock", "name": HOSTNAME, "req_id": "r2"}),
        ("unlock", {**base, "action": "unlock", "name": HOSTNAME}),
        (
            "set_daily_limit",
            {**base, "action": "set", "var": "daily_limit", "val": 120, "name": HOSTNAME},
        ),
        (
            "set_bed_time_quoted",
            {**base, "action": "set", "var": "bed_time", "val": "21:30", "name": HOSTNAME},
        ),
        (
            "set_manual_lock_bool",
            {**base, "action": "set", "var": "manual_lock", "val": True, "name": HOSTNAME},
        ),
        ("clear", {**base, "action": "clear", "var": "daily_limit", "name": HOSTNAME}),
        ("extend", {**base, "action": "extend", "val": 15, "name": HOSTNAME}),
        ("shutdown_default", {**base, "action": "shutdown", "name": HOSTNAME}),
        ("shutdown_seconds", {**base, "action": "shutdown", "val": 30, "name": HOSTNAME}),
        (
            "message_plain",
            {**base, "action": "message", "val": "Dinner time!", "name": HOSTNAME},
        ),
        (
            "message_unicode_multiline",
            {
                **base,
                "action": "message",
                "val": 'Dinner 🍝\nsay "hi"\tnow\\',
                "name": HOSTNAME,
            },
        ),
        (
            "message_trailing_newline",
            {**base, "action": "message", "val": "hello\n", "name": HOSTNAME},
        ),
        ("get_logs_default", {**base, "action": "get_logs"}),
        ("get_logs_tail", {**base, "action": "get_logs", "tail": 100, "name": HOSTNAME}),
        (
            "unicode_secret",
            {
                **base,
                "secret": SECRET_UNICODE,
                "action": "unlock",
                "name": HOSTNAME,
                "nonce": NONCE_2,
            },
        ),
        (
            "unicode_hostname",
            {**base, "action": "lock", "name": "Kinder-PC ü"},
        ),
    ]


def build_request_cases() -> list[dict[str, Any]]:
    return [
        {"name": name, "args": kwargs, "body": proto.build_request(**kwargs)}
        for name, kwargs in build_request_kwargs()
    ]


def signed_body(nodes: list[Node], secret: str = SECRET) -> str:
    """Sign arbitrary nodes the way a well-behaved peer would (for malformed-frame cases)."""
    signed = list(nodes)
    signed.append(proto._auth_node(signed, secret))  # pyright: ignore[reportPrivateUsage]
    return proto.serialize(signed)


def _req_nodes(
    action: Any = "unlock",
    *,
    version: Any = 3,
    req_id: Any = "q1",
    name: Any = HOSTNAME,
    timestamp: Any = NOW,
    nonce: Any = NONCE,
    extra: list[Node] | None = None,
) -> list[Node]:
    nodes: list[Node] = []
    if version is not None:
        nodes.append(Node("v", [version]))
    if req_id is not None:
        nodes.append(Node("id", [req_id]))
    if name is not None:
        nodes.append(Node("name", [name]))
    if timestamp is not None:
        nodes.append(Node("timestamp", [timestamp]))
    if nonce is not None:
        nodes.append(Node("nonce", [nonce]))
    if action is not None:
        nodes.append(Node("action", [action]))
    nodes.extend(extra or [])
    return nodes


def parse_request_inputs() -> list[tuple[str, dict[str, Any]]]:
    """Cases for ``parse_request``: each is ``{body, secret, hostname, now}``."""
    base = {"secret": SECRET, "hostname": HOSTNAME, "now": NOW}
    cases: list[tuple[str, dict[str, Any]]] = []

    # Every well-formed request built above must parse on the matching host.
    for name, kwargs in build_request_kwargs():
        host = kwargs.get("name") or HOSTNAME
        cases.append(
            (
                f"built_{name}",
                {**base, "secret": kwargs["secret"], "hostname": host, "body": None, "build": name},
            )
        )

    def case(name: str, body: str, **overrides: Any) -> None:
        cases.append((name, {**base, "body": body, **overrides}))

    good = signed_body(_req_nodes("unlock"))
    case("window_exact_now", good)
    case("window_plus_60", good, now=NOW + 60)
    case("window_minus_60", good, now=NOW - 60)
    case("window_plus_61_stale", good, now=NOW + 61)
    case("window_minus_61_stale", good, now=NOW - 61)
    case("wrong_secret", good, secret="not-the-secret")
    case("wrong_hostname", good, hostname="other-pc")
    case(
        "unnamed_read_any_host",
        signed_body(_req_nodes("get", name=None, extra=[Node("var", ["name"])])),
        hostname="other-pc",
    )
    case("unnamed_write_requires_name", signed_body(_req_nodes("lock", name=None)))
    case(
        "unnamed_write_requires_name_set",
        signed_body(
            _req_nodes("set", name=None, extra=[Node("var", ["daily_limit"]), Node("val", [60])])
        ),
    )
    case("tampered_val", good.replace("action unlock", "action lock"))
    case("not_a_frame", "this is not kdl {")
    case("empty_body", "")
    case("unterminated_string_body", 'v 3\nname "oops')

    no_auth = proto.serialize(_req_nodes("unlock"))
    case("missing_auth", no_auth)

    def with_auth(nodes: list[Node], auth_children: list[Node]) -> str:
        return proto.serialize([*nodes, Node("auth", children=auth_children)])

    case(
        "missing_signature",
        with_auth(
            _req_nodes("unlock"),
            [Node("algorithm", ["hmac-sha256"]), Node("key_id", ["kid-pc-monitor-shared-secret"])],
        ),
    )
    case("garbage_signature", with_auth(_req_nodes("unlock"), [Node("signature", ["AAAA"])]))
    case("non_ascii_signature", with_auth(_req_nodes("unlock"), [Node("signature", ["sigé"])]))
    case("missing_timestamp", signed_body(_req_nodes("unlock", timestamp=None)))
    case("missing_nonce", signed_body(_req_nodes("unlock", nonce=None)))
    case("timestamp_is_string", signed_body(_req_nodes("unlock", timestamp="1710000000")))
    case("timestamp_is_bool", signed_body(_req_nodes("unlock", timestamp=True)))
    case("nonce_too_short", signed_body(_req_nodes("unlock", nonce="abcdef")))
    case("nonce_not_hex", signed_body(_req_nodes("unlock", nonce="z" * 32)))
    case("nonce_is_int", signed_body(_req_nodes("unlock", nonce=123456)))
    case("missing_version", signed_body(_req_nodes("unlock", version=None)))
    case("version_is_string", signed_body(_req_nodes("unlock", version="3")))
    case("version_is_bool", signed_body(_req_nodes("unlock", version=True)))
    case("version_2_unsupported", signed_body(_req_nodes("unlock", version=2)))
    case("version_4_unsupported", signed_body(_req_nodes("unlock", version=4)))
    case(
        "unsupported_version_keeps_id", signed_body(_req_nodes("unlock", version=9, req_id="keep"))
    )
    case("unknown_action", signed_body(_req_nodes("reboot")))
    case("action_is_int", signed_body(_req_nodes(5)))
    case("missing_action", signed_body(_req_nodes(None)))
    case("numeric_id_is_stringified", signed_body(_req_nodes("unlock", req_id=1234)))
    case("no_id", signed_body(_req_nodes("unlock", req_id=None)))

    def get(var: Any) -> str:
        return signed_body(_req_nodes("get", extra=[Node("var", [var])] if var is not None else []))

    case("get_settings", get("settings"))
    case("get_every_variable", get("accumulated_seconds"))
    case("get_missing_var", get(None))
    case("get_unknown_var", get("nope"))
    case("get_var_is_int", get(5))

    def with_var(action: str, var: Any, val: Any = None) -> str:
        extra = [Node("var", [var])]
        if val is not None:
            extra.append(Node("val", [val]))
        return signed_body(_req_nodes(action, extra=extra))

    case("set_ok", with_var("set", "daily_limit", 90))
    case("set_missing_val", with_var("set", "daily_limit"))
    case("set_unknown_var", with_var("set", "nope", 1))
    case("set_missing_var", signed_body(_req_nodes("set", extra=[Node("val", [1])])))
    case("set_read_only_var_passes_parse", with_var("set", "status", "LOCKED"))
    case("clear_ok", with_var("clear", "daily_limit"))
    case("clear_missing_var", signed_body(_req_nodes("clear")))
    case("clear_unknown_var", with_var("clear", "nope"))
    case("extend_missing_val", signed_body(_req_nodes("extend")))
    case("extend_ok", signed_body(_req_nodes("extend", extra=[Node("val", [10])])))
    case("message_missing_val", signed_body(_req_nodes("message")))
    case("message_ok", signed_body(_req_nodes("message", extra=[Node("val", ["hi\n"])])))
    case("shutdown_no_val_ok", signed_body(_req_nodes("shutdown")))
    case(
        "val_null_counts_as_missing", signed_body(_req_nodes("extend", extra=[Node("val", [None])]))
    )

    def logs(tail: Any) -> str:
        return signed_body(_req_nodes("get_logs", extra=[Node("tail", [tail])]))

    case("tail_1", logs(1))
    case("tail_5000", logs(5000))
    case("tail_0", logs(0))
    case("tail_negative", logs(-3))
    case("tail_5001", logs(5001))
    case("tail_numeric_string", logs("12"))
    case("tail_text", logs("abc"))
    case("tail_bool", logs(True))
    case("tail_null_ignored", logs(None))
    case("get_logs_unnamed_ok", signed_body(_req_nodes("get_logs", name=None)))

    case(
        "duplicate_fields_last_wins",
        signed_body(
            _req_nodes("get", extra=[Node("var", ["name"]), Node("var", ["settings"])]),
        ),
    )
    case(
        "unknown_extra_fields_ignored",
        signed_body(_req_nodes("unlock", extra=[Node("future", ["thing"])])),
    )
    case(
        "extra_block_field_is_signed",
        signed_body(_req_nodes("unlock", extra=[Node("meta", children=[Node("x", [1])])])),
    )
    case(
        "unicode_hostname_match",
        signed_body(_req_nodes("lock", name="Kinder-PC ü")),
        hostname="Kinder-PC ü",
    )
    case("numeric_name_stringified", signed_body(_req_nodes("lock", name=42)), hostname="42")
    return cases


def request_json(req: proto.Request) -> dict[str, Any]:
    return {
        "version": req.version,
        "id": req.id,
        "action": req.action,
        "var": req.var,
        "val": req.val,
        "name": req.name,
        "timestamp": req.timestamp,
        "nonce": req.nonce,
        "tail": req.tail,
    }


def parse_request_cases() -> list[dict[str, Any]]:
    builds = {c["name"]: c["body"] for c in build_request_cases()}
    out: list[dict[str, Any]] = []
    for name, spec in parse_request_inputs():
        body = builds[spec["build"]] if spec.get("build") else spec["body"]
        case: dict[str, Any] = {
            "name": name,
            "secret": spec["secret"],
            "hostname": spec["hostname"],
            "now": spec["now"],
            "body": body,
        }
        try:
            req = proto.parse_request(
                body, secret=spec["secret"], hostname=spec["hostname"], now=spec["now"]
            )
        except ProtocolError as exc:
            case["error"] = error_json(exc)
        else:
            case["request"] = request_json(req)
        out.append(case)
    return out


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
def _settings_block() -> Node:
    return Node(
        "settings",
        children=[
            Node("name", [HOSTNAME]),
            Node("status", ["UNLOCKED"]),
            Node("current_user", ["kid"]),
            Node("daily_limit", [120]),
            Node("bed_time", ["21:00"]),
            Node("manual_lock", [False]),
            Node("wake_time", ["07:00"]),
            Node("cumulative_extension", [0]),
            Node("accumulated_seconds", [1234]),
            Node("time_remaining", [None]),
            Node("enforcement_active", [False]),
            Node("enforcement_reason", [None]),
            Node("access_status", ["Unlocked"]),
        ],
    )


def _logs_block(lines: list[str], truncated: bool = True) -> Node:
    return Node(
        "logs",
        children=[
            Node("path", ["C:\\Users\\kid\\AppData\\Local\\KidPCMonitor\\pc_control.log"]),
            Node("truncated", [truncated]),
            Node("lines", lines),
        ],
    )


def response_content_inputs() -> list[tuple[str, list[Node], dict[str, Any]]]:
    return [
        ("ok_int", proto.ok_content(120), {"req_id": "r1"}),
        ("ok_string_bare", proto.ok_content("locked"), {"req_id": "r2"}),
        ("ok_string_quoted", proto.ok_content("Locked — past bedtime"), {}),
        ("ok_bool", proto.ok_content(True), {}),
        ("ok_null", proto.ok_content(None), {}),
        ("ok_trailing_newline", proto.ok_content("done\n"), {"req_id": "nl"}),
        ("ok_hostname_result", proto.ok_content(HOSTNAME), {"req_id": "n"}),
        ("settings", proto.block_content(_settings_block()), {"req_id": "s1"}),
        ("capabilities", proto.capabilities_content(), {"req_id": "caps"}),
        (
            "error_invalid_value",
            proto.error_content(proto.INVALID_VALUE, "minutes must be between 1 and 1440"),
            {"req_id": "e1"},
        ),
        (
            "error_auth_failed_trailing_newline",
            proto.error_content(proto.AUTHENTICATION_FAILED, "signature did not verify.\n"),
            {},
        ),
        ("error_no_id", proto.error_content(proto.INVALID_REQUEST, "could not parse request"), {}),
        (
            "logs",
            proto.block_content(
                _logs_block(
                    [
                        "[2026-05-31 12:00:00] INFO kid_pc_monitor: started",
                        'quote " and \\ backslash',
                        "ünï 🔑",
                        "plain",
                    ]
                )
            ),
            {"req_id": "lg"},
        ),
        ("logs_empty", proto.block_content(_logs_block([], truncated=False)), {"req_id": "lg0"}),
        ("unicode_secret", proto.ok_content("ok"), {"secret": SECRET_UNICODE, "nonce": NONCE_2}),
        (
            "unicode_hostname",
            proto.ok_content("ok"),
            {"hostname": "Kinder-PC ü"},
        ),
    ]


def build_response_cases() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, content, overrides in response_content_inputs():
        args: dict[str, Any] = {
            "secret": SECRET,
            "hostname": HOSTNAME,
            "req_id": None,
            "timestamp": NOW,
            "nonce": NONCE,
            "version": 3,
        }
        args.update(overrides)
        body = proto.sign_response(
            content,
            secret=args["secret"],
            hostname=args["hostname"],
            req_id=args["req_id"],
            timestamp=args["timestamp"],
            nonce=args["nonce"],
            version=args["version"],
        )
        out.append({"name": name, "content": nodes_json(content), "args": args, "body": body})
    return out


def response_json(resp: proto.Response) -> dict[str, Any]:
    logs = None
    if resp.logs is not None:
        logs = {
            "path": resp.logs.path,
            "truncated": resp.logs.truncated,
            "lines": resp.logs.lines,
        }
    return {
        "version": resp.version,
        "id": resp.id,
        "status": resp.status,
        "result": resp.result,
        "error_code": resp.error_code,
        "error_message": resp.error_message,
        "settings": resp.settings,
        "logs": logs,
        "name": resp.name,
        "timestamp": resp.timestamp,
        "nonce": resp.nonce,
    }


def parse_response_cases() -> list[dict[str, Any]]:
    built = {c["name"]: c for c in build_response_cases()}
    out: list[dict[str, Any]] = []

    def case(
        name: str,
        body: str,
        *,
        secret: str = SECRET,
        expected_name: str | None = None,
        expected_version: int | None = None,
        now: int = NOW,
    ) -> None:
        entry: dict[str, Any] = {
            "name": name,
            "body": body,
            "secret": secret,
            "expected_name": expected_name,
            "expected_version": expected_version,
            "now": now,
        }
        try:
            resp = proto.parse_response(
                body,
                secret=secret,
                expected_name=expected_name,
                expected_version=expected_version,
                now=now,
            )
        except ProtocolError as exc:
            entry["error"] = error_json(exc)
        else:
            entry["response"] = response_json(resp)
        out.append(entry)

    for name, spec in built.items():
        args = spec["args"]
        case(
            f"built_{name}",
            spec["body"],
            secret=args["secret"],
            expected_name=args["hostname"],
            expected_version=3,
        )
    ok = built["ok_int"]["body"]
    case("no_expected_name", ok)
    case("wrong_expected_name", ok, expected_name="other-pc")
    case("wrong_secret", ok, secret="nope")
    case("stale_plus_61", ok, now=NOW + 61)
    case("stale_minus_61", ok, now=NOW - 61)
    case("edge_plus_60", ok, now=NOW + 60)
    case("expected_version_mismatch", ok, expected_version=4)
    case("tampered", ok.replace("result 120", "result 121"))
    case("unparseable_raises_invalid_request", 'v 3\nname "oops')

    def resp_nodes(
        *extra: Node, version: Any = 3, name: Any = HOSTNAME, ts: Any = NOW
    ) -> list[Node]:
        nodes = [Node("v", [version]), Node("id", ["x"])] if version is not None else []
        if name is not None:
            nodes.append(Node("name", [name]))
        nodes.append(Node("timestamp", [ts]))
        nodes.append(Node("nonce", [NONCE]))
        nodes.extend(extra)
        return nodes

    case("unsupported_version", signed_body(resp_nodes(Node("status", ["ok"]), version=2)))
    case("missing_version", signed_body(resp_nodes(Node("status", ["ok"]), version=None)))
    case("missing_name_no_expectation", signed_body(resp_nodes(Node("status", ["ok"]), name=None)))
    case(
        "missing_name_with_expectation",
        signed_body(resp_nodes(Node("status", ["ok"]), name=None)),
        expected_name=HOSTNAME,
    )
    case("missing_status_defaults_to_failure", signed_body(resp_nodes(Node("result", [1]))))
    case("status_is_bool", signed_body(resp_nodes(Node("status", [True]))))
    case("no_auth", proto.serialize(resp_nodes(Node("status", ["ok"]))))
    case(
        "error_block_partial",
        signed_body(
            resp_nodes(
                Node("status", ["failure"]), Node("error", children=[Node("code", ["forbidden"])])
            )
        ),
    )
    case(
        "error_code_is_int",
        signed_body(
            resp_nodes(
                Node("status", ["failure"]),
                Node("error", children=[Node("code", [7]), Node("message", [None])]),
            )
        ),
    )
    case(
        "logs_truthy_variants",
        signed_body(
            resp_nodes(
                Node("status", ["ok"]),
                Node(
                    "logs",
                    children=[
                        Node("path", [5]),
                        Node("truncated", ["yes"]),
                        Node("lines", [1, True, None, "s"]),
                    ],
                ),
            )
        ),
    )
    case(
        "logs_without_lines",
        signed_body(
            resp_nodes(
                Node("status", ["ok"]),
                Node("logs", children=[Node("truncated", [0])]),
            )
        ),
    )
    case(
        "duplicate_result_last_wins",
        signed_body(resp_nodes(Node("status", ["ok"]), Node("result", [1]), Node("result", [2]))),
    )
    case(
        "hostname_numeric_stringified",
        signed_body(resp_nodes(Node("status", ["ok"]), name=42)),
        expected_name="42",
    )
    return out


PEEK_VERSION_BODIES: list[str] = [
    "v 3",
    "v 3\naction get",
    "id x\nv 3",
    "v 2",
    "v 9\nid x",
    "v true",
    'v "3"',
    "id x",
    "",
    'v 3\na "oops',
    "a {" * 5000,
    "v\nv 3",
    "v 2\nv 3",
]


def peek_version_cases() -> list[dict[str, Any]]:
    return [{"body": body, "version": proto.peek_version(body)} for body in PEEK_VERSION_BODIES]


# ---------------------------------------------------------------------------
# Whole file
# ---------------------------------------------------------------------------
def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden protocol vectors generated from kid_pc_monitor.agent_protocol by "
            "tests/protocol_vectors_gen.py. Do not edit by hand."
        ),
        "constants": {
            "protocol_version": proto.PROTOCOL_VERSION,
            "max_frame_bytes": proto.MAX_FRAME_BYTES,
            "max_log_tail_lines": proto.MAX_LOG_TAIL_LINES,
            "timestamp_window_seconds": agent_auth.TIMESTAMP_WINDOW_SECONDS,
            "key_id": agent_auth.DEFAULT_KEY_ID,
            "algorithm": agent_auth.ALGORITHM,
            "actions": list(proto.ACTIONS),
            "action_descriptions": proto.ACTIONS,
            "variables": list(proto.VARIABLES),
            "variable_descriptions": proto.VARIABLES,
            "write_actions": sorted(proto.WRITE_ACTIONS),
        },
        "format_value": format_value_cases(),
        "serialize": serialize_cases(),
        "parse": parse_cases(),
        "frame_encode": frame_encode_cases(),
        "frame_inspect": frame_inspect_cases(),
        "signature": signature_cases(),
        "nonce": nonce_cases(),
        "timestamp_window": window_cases(),
        "build_request": build_request_cases(),
        "peek_version": peek_version_cases(),
        "parse_request": parse_request_cases(),
        "build_response": build_response_cases(),
        "parse_response": parse_response_cases(),
    }


def render(vectors: dict[str, Any]) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the file is out of date")
    args = parser.parse_args()
    text = render(build_vectors())
    if args.check:
        current = VECTORS_PATH.read_text(encoding="utf-8") if VECTORS_PATH.exists() else ""
        if current != text:
            print(
                f"{VECTORS_PATH} is out of date; run tests/protocol_vectors_gen.py", file=sys.stderr
            )
            return 1
        return 0
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

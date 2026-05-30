"""Structured request/response protocol for kid PC agents (version 2).

The wire format is a length-prefixed body written in a small subset of
`KDL <https://kdl.dev/spec>`_.  Each line is a node: a bare identifier name
followed by a single value, e.g. ``action set``.  Blocks (``{ ... }``) carry
nested nodes, used for ``error``, ``settings``, ``list_capabilities``, and the
``auth`` signature.  The subset deliberately omits comments, type annotations,
floating point numbers, and KDL's multi-line string syntax.

Protocol version 2 adds mutual authentication: every request and every
response carries an ``auth`` block with an HMAC-SHA256 signature, plus a
``timestamp`` and ``nonce`` so that captured frames cannot be replayed or
tampered with.  The cryptographic primitives live in
:mod:`kid_pc_monitor.agent_auth`; this module wires them into the frame
format.  See ``docs/agent-protocol.md`` for the full design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from kid_pc_monitor import agent_auth

PROTOCOL_VERSION = 2

# Reject absurd length prefixes outright; real frames are well under 1 KiB.
MAX_FRAME_BYTES = 64 * 1024

# ---------------------------------------------------------------------------
# Error codes (see docs/agent-protocol.md)
# ---------------------------------------------------------------------------
INVALID_REQUEST = "invalid_request"
UNSUPPORTED_VERSION = "unsupported_version"
UNKNOWN_ACTION = "unknown_action"
UNKNOWN_VARIABLE = "unknown_variable"
INVALID_VALUE = "invalid_value"
FORBIDDEN = "forbidden"
INTERNAL_ERROR = "internal_error"
# v2 authentication failures.
AUTHENTICATION_REQUIRED = "authentication_required"
AUTHENTICATION_FAILED = "authentication_failed"
STALE_TIMESTAMP = "stale_timestamp"

# ---------------------------------------------------------------------------
# Actions and variables
# ---------------------------------------------------------------------------
ACTIONS: dict[str, str] = {
    "get": 'get a single variable or "settings" to get all variables',
    "set": "set a single variable to a new value",
    "clear": "clear a single variable",
    "lock": "immediately lock",
    "unlock": "release a manual lock",
    "extend": "add minutes of extra allowance for today (val=minutes)",
    "message": "show a popup message on the PC (val=text)",
    "shutdown": "shut down the PC after a warning (val=seconds, default 60)",
    "list_capabilities": "describe supported actions and variables",
}

# Write/destructive actions must carry a ``name`` that matches the agent's
# hostname (see "Cross-PC replay" in docs/agent-protocol.md).  Read-only
# actions may omit ``name`` so the panel can discover an agent it has never
# spoken to before.
WRITE_ACTIONS = frozenset(
    {"set", "clear", "lock", "unlock", "extend", "shutdown", "message"}
)

# Default warning period before shutdown, in seconds.
DEFAULT_SHUTDOWN_SECONDS = 60

# Every readable variable, in display order, with a human description.
VARIABLES: dict[str, str] = {
    "name": "read-only, name of computer",
    "status": "read-only, the lock status (LOCKED/UNLOCKED)",
    "current_user": "read-only, the username of the currently logged-in user",
    "daily_limit": "current daily limit in minutes",
    "bed_time": "bed time, at which the computer will be locked",
    "manual_lock": "boolean, whether a manual lock is in effect",
    "wake_time": "time, at which the computer can be used the following morning",
    "cumulative_extension": "read-only, a running total of extension seconds today",
    "accumulated_seconds": "read-only, a running total of active seconds used today",
    "time_remaining": "read-only, minutes remaining today (or null)",
}

WRITABLE_VARIABLES = frozenset({"daily_limit", "bed_time", "manual_lock", "wake_time"})
CLEARABLE_VARIABLES = frozenset(
    {"daily_limit", "bed_time", "manual_lock", "cumulative_extension"}
)

# A daily limit outside this range is almost certainly a mistake.
MIN_DAILY_LIMIT = 1
MAX_DAILY_LIMIT = 1440


class ProtocolError(Exception):
    """A protocol-level failure carrying an error code and message.

    ``req_id`` is the request id to echo in the failure response, when known.
    """

    def __init__(self, code: str, message: str, req_id: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.req_id = req_id


# ===========================================================================
# KDL-subset document model
# ===========================================================================
@dataclass
class Node:
    """A single KDL node: a name, zero or more scalar args, and child nodes."""

    name: str
    args: list[Any] = field(default_factory=list)
    children: list["Node"] = field(default_factory=list)

    @property
    def arg(self) -> Any:
        """The first (and, for this protocol, only) argument, or None."""
        return self.args[0] if self.args else None

    def child_map(self) -> dict[str, Any]:
        """Map child node names to their first argument."""
        return {child.name: child.arg for child in self.children}


_BARE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:+\-]*$")
_KEYWORDS = {"true", "false", "null"}


def _is_bare(text: str) -> bool:
    """True when ``text`` can be emitted as an unquoted identifier."""
    return bool(_BARE_RE.match(text)) and text not in _KEYWORDS


def _escape(text: str) -> str:
    out = text.replace("\\", "\\\\").replace('"', '\\"')
    return out.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")


def format_value(value: Any) -> str:
    """Render a scalar Python value as a KDL token."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if _is_bare(text):
        return text
    return '"' + _escape(text) + '"'


def serialize(nodes: list[Node]) -> str:
    """Serialize a list of nodes to a KDL-subset document body (no trailing NL)."""
    lines: list[str] = []
    _serialize_into(nodes, 0, lines)
    return "\n".join(lines)


def _serialize_into(nodes: list[Node], indent: int, lines: list[str]) -> None:
    pad = " " * indent
    for node in nodes:
        parts = [node.name] + [format_value(arg) for arg in node.args]
        prefix = pad + " ".join(parts)
        if node.children:
            lines.append(prefix + " {")
            _serialize_into(node.children, indent + 2, lines)
            lines.append(pad + "}")
        else:
            lines.append(prefix)


def _unescape(text: str, start: int) -> tuple[str, int]:
    """Decode one escape sequence after the backslash at ``start - 1``."""
    simple = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/"}
    ch = text[start]
    if ch in simple:
        return simple[ch], start + 1
    if ch == "u" and start + 1 < len(text) and text[start + 1] == "{":
        end = text.find("}", start + 2)
        if end == -1:
            raise ProtocolError(INVALID_REQUEST, "unterminated unicode escape")
        try:
            return chr(int(text[start + 2 : end], 16)), end + 1
        except ValueError as exc:
            raise ProtocolError(INVALID_REQUEST, "bad unicode escape") from exc
    raise ProtocolError(INVALID_REQUEST, f"unsupported escape: \\{ch}")


def _parse_bare(word: str) -> Any:
    if word == "true":
        return True
    if word == "false":
        return False
    if word == "null":
        return None
    try:
        return int(word)
    except ValueError:
        return word


_DELIMS = set(' \t\n\r{};"')


def _tokenize(text: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t":
            i += 1
        elif ch in "\n\r":
            tokens.append(("NL", None))
            i += 1
        elif ch == ";":
            tokens.append(("NL", None))
            i += 1
        elif ch == "{":
            tokens.append(("LB", None))
            i += 1
        elif ch == "}":
            tokens.append(("RB", None))
            i += 1
        elif ch == '"':
            i += 1
            buf: list[str] = []
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    decoded, i = _unescape(text, i + 1)
                    buf.append(decoded)
                else:
                    buf.append(text[i])
                    i += 1
            if i >= n:
                raise ProtocolError(INVALID_REQUEST, "unterminated string")
            i += 1  # closing quote
            tokens.append(("VAL", "".join(buf)))
        else:
            start = i
            while i < n and text[i] not in _DELIMS:
                i += 1
            tokens.append(("VAL", _parse_bare(text[start:i])))
    return tokens


def parse(text: str) -> list[Node]:
    """Parse a KDL-subset document body into a list of nodes."""
    tokens = _tokenize(text)
    pos = 0

    def parse_nodes(in_block: bool) -> list[Node]:
        nonlocal pos
        nodes: list[Node] = []
        while pos < len(tokens):
            kind, value = tokens[pos]
            if kind == "NL":
                pos += 1
                continue
            if kind == "RB":
                if not in_block:
                    raise ProtocolError(INVALID_REQUEST, "unexpected '}'")
                pos += 1
                return nodes
            if kind == "LB":
                raise ProtocolError(INVALID_REQUEST, "unexpected '{'")
            # kind == VAL: this token names the node.
            if not isinstance(value, str):
                raise ProtocolError(INVALID_REQUEST, "node name must be an identifier")
            pos += 1
            args: list[Any] = []
            while pos < len(tokens) and tokens[pos][0] == "VAL":
                args.append(tokens[pos][1])
                pos += 1
            children: list[Node] = []
            if pos < len(tokens) and tokens[pos][0] == "LB":
                pos += 1
                children = parse_nodes(in_block=True)
            nodes.append(Node(value, args, children))
        if in_block:
            raise ProtocolError(INVALID_REQUEST, "missing '}'")
        return nodes

    return parse_nodes(in_block=False)


# ===========================================================================
# Framing
# ===========================================================================
COMPLETE = "complete"
INCOMPLETE = "incomplete"
NOT_FRAME = "not_frame"


def encode_frame(body: str) -> bytes:
    """Prefix a body with its byte length on its own line."""
    payload = body.encode("utf-8")
    return f"{len(payload)}\n".encode("ascii") + payload


def inspect_frame(buffer: bytes) -> tuple[str, str | None, bytes]:
    """Classify the head of ``buffer`` as a length-prefixed frame.

    Returns ``(status, body, rest)``:
    - ``COMPLETE``: ``body`` is the decoded frame, ``rest`` is leftover bytes.
    - ``INCOMPLETE``: a valid prefix but not all body bytes have arrived yet.
    - ``NOT_FRAME``: the head is not a numeric length prefix.
    """
    newline = buffer.find(b"\n")
    if newline == -1:
        # A bare run of digits may be a prefix still arriving; anything else
        # cannot become a frame.
        if buffer and buffer.isdigit():
            return INCOMPLETE, None, buffer
        return NOT_FRAME, None, buffer
    head = buffer[:newline]
    if not head.isdigit():
        return NOT_FRAME, None, buffer
    length = int(head)
    if length > MAX_FRAME_BYTES:
        raise ProtocolError(INVALID_REQUEST, "frame too large")
    body = buffer[newline + 1 :]
    if len(body) < length:
        return INCOMPLETE, None, buffer
    return COMPLETE, body[:length].decode("utf-8"), body[length:]


def read_frame(sock: Any) -> str:
    """Read exactly one length-prefixed frame from a blocking socket."""
    buffer = b""
    while b"\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProtocolError(INVALID_REQUEST, "connection closed before length prefix")
        buffer += chunk
        if len(buffer) > MAX_FRAME_BYTES:
            raise ProtocolError(INVALID_REQUEST, "length prefix too long")
    while True:
        status, body, _rest = inspect_frame(buffer)
        if status == COMPLETE:
            return body  # type: ignore[return-value]
        if status == NOT_FRAME:
            raise ProtocolError(INVALID_REQUEST, "expected a length-prefixed frame")
        chunk = sock.recv(4096)
        if not chunk:
            raise ProtocolError(INVALID_REQUEST, "connection closed mid-frame")
        buffer += chunk


# ===========================================================================
# Authentication (protocol v2)
# ===========================================================================
def _split_auth(nodes: list[Node]) -> tuple[Node | None, list[Node]]:
    """Separate the (first) ``auth`` node from the rest, preserving order."""
    auth: Node | None = None
    rest: list[Node] = []
    for node in nodes:
        if node.name == "auth" and auth is None:
            auth = node
        else:
            rest.append(node)
    return auth, rest


def _auth_node(signed_nodes: list[Node], secret: str, name: str | None) -> Node:
    """Build the ``auth`` block that signs ``signed_nodes`` (which exclude it)."""
    canonical = serialize(signed_nodes)
    key = agent_auth.derive_key(secret, name)
    signature = agent_auth.compute_signature(key, canonical)
    return Node(
        "auth",
        children=[
            Node("algorithm", [agent_auth.ALGORITHM]),
            Node("key_id", [agent_auth.DEFAULT_KEY_ID]),
            Node("signature", [signature]),
        ],
    )


def verify_frame(
    nodes: list[Node],
    secret: str,
    *,
    req_id: str | None = None,
    now: int | None = None,
) -> str | None:
    """Validate the auth, timestamp, and nonce of a parsed v2 frame.

    Returns the frame's ``name`` (or ``None`` for an unnamed read-only frame).
    Raises :class:`ProtocolError` with the appropriate v2 code on any failure.
    The caller is responsible for matching the returned name against the
    expected hostname.
    """
    auth, rest = _split_auth(nodes)
    fields = {node.name: node.arg for node in rest}

    name = fields.get("name")
    if name is not None:
        name = str(name)

    if auth is None:
        raise ProtocolError(AUTHENTICATION_REQUIRED, "missing auth block", req_id)

    timestamp = fields.get("timestamp")
    nonce = fields.get("nonce")
    if timestamp is None:
        raise ProtocolError(AUTHENTICATION_REQUIRED, "missing timestamp", req_id)
    if nonce is None:
        raise ProtocolError(AUTHENTICATION_REQUIRED, "missing nonce", req_id)
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ProtocolError(INVALID_REQUEST, "timestamp must be an integer", req_id)
    if not agent_auth.is_valid_nonce(nonce):
        raise ProtocolError(INVALID_REQUEST, "nonce must be hex randomness", req_id)

    signature = auth.child_map().get("signature")
    if signature is None:
        raise ProtocolError(AUTHENTICATION_REQUIRED, "missing signature", req_id)

    canonical = serialize(rest)
    key = agent_auth.derive_key(secret, name)
    if not agent_auth.verify_signature(key, canonical, str(signature)):
        raise ProtocolError(AUTHENTICATION_FAILED, "signature did not verify", req_id)

    if not agent_auth.timestamp_in_window(timestamp, now=now):
        raise ProtocolError(STALE_TIMESTAMP, "timestamp outside allowed window", req_id)

    return name


# ===========================================================================
# Requests
# ===========================================================================
@dataclass
class Request:
    version: int
    id: str | None
    action: str
    var: str | None = None
    val: Any = None
    name: str | None = None
    timestamp: int | None = None
    nonce: str | None = None


def build_request(
    action: str,
    *,
    secret: str,
    var: str | None = None,
    val: Any = None,
    req_id: str | None = None,
    name: str | None = None,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> str:
    """Build and sign a v2 request body for a client to send.

    ``name`` is the target agent's hostname.  It is required for write actions
    and optional for read-only ones; when present it also selects the
    per-agent signing key.
    """
    nodes = [Node("v", [PROTOCOL_VERSION])]
    if req_id is not None:
        nodes.append(Node("id", [req_id]))
    if name is not None:
        nodes.append(Node("name", [name]))
    nodes.append(
        Node("timestamp", [agent_auth.now_timestamp() if timestamp is None else timestamp])
    )
    nodes.append(Node("nonce", [agent_auth.make_nonce() if nonce is None else nonce]))
    nodes.append(Node("action", [action]))
    if var is not None:
        nodes.append(Node("var", [var]))
    if val is not None:
        nodes.append(Node("val", [val]))
    nodes.append(_auth_node(nodes, secret, name))
    return serialize(nodes)


def parse_request(
    body: str,
    *,
    secret: str,
    hostname: str,
    now: int | None = None,
) -> Request:
    """Parse, authenticate, and structurally validate a v2 request body.

    Raises :class:`ProtocolError` for malformed requests, unsupported versions,
    failed authentication, and unknown actions/variables.  Value-level checks
    happen in :func:`dispatch`.  ``hostname`` is the agent's own name, used to
    reject frames addressed to a different PC.
    """
    try:
        nodes = parse(body)
    except ProtocolError:
        raise ProtocolError(INVALID_REQUEST, "could not parse request")

    fields = {node.name: node.arg for node in nodes if node.name != "auth"}
    req_id = fields.get("id")
    if req_id is not None:
        req_id = str(req_id)

    version = fields.get("v")
    if version is None:
        raise ProtocolError(INVALID_REQUEST, "missing protocol version", req_id)
    if version != PROTOCOL_VERSION:
        raise ProtocolError(
            UNSUPPORTED_VERSION,
            f"protocol version {version!r} is not supported",
            req_id,
        )

    # Authenticate before acting on anything in the frame.
    name = verify_frame(nodes, secret, req_id=req_id, now=now)

    action = fields.get("action")
    if action not in ACTIONS:
        raise ProtocolError(UNKNOWN_ACTION, f"unknown action: {action!r}", req_id)

    # Destination binding: a named frame must target this agent; write actions
    # must always be named (see "Cross-PC replay" / "Discovery handshake").
    if name is not None and name != hostname:
        raise ProtocolError(
            AUTHENTICATION_FAILED,
            "frame addressed to a different agent",
            req_id,
        )
    if action in WRITE_ACTIONS and name is None:
        raise ProtocolError(
            AUTHENTICATION_REQUIRED,
            f"{action} requires a name identifying the target agent",
            req_id,
        )

    var = fields.get("var")
    if var is not None:
        var = str(var)
    val = fields.get("val")

    if action == "get":
        if var is None:
            raise ProtocolError(INVALID_REQUEST, "get requires a variable", req_id)
        if var != "settings" and var not in VARIABLES:
            raise ProtocolError(UNKNOWN_VARIABLE, f"unknown variable: {var}", req_id)
    elif action in ("set", "clear"):
        if var is None:
            raise ProtocolError(INVALID_REQUEST, f"{action} requires a variable", req_id)
        if var not in VARIABLES:
            raise ProtocolError(UNKNOWN_VARIABLE, f"unknown variable: {var}", req_id)
        if action == "set" and val is None:
            raise ProtocolError(INVALID_REQUEST, "set requires a value", req_id)
    elif action == "extend" and val is None:
        raise ProtocolError(INVALID_REQUEST, "extend requires minutes", req_id)
    elif action == "message" and val is None:
        raise ProtocolError(INVALID_REQUEST, "message requires text", req_id)

    return Request(
        PROTOCOL_VERSION,
        req_id,
        action,
        var,
        val,
        name=name,
        timestamp=fields.get("timestamp"),
        nonce=fields.get("nonce"),
    )


# ===========================================================================
# Responses
# ===========================================================================
# Response builders return the *content* nodes (``status`` plus any payload).
# The signed v2 envelope (``v``/``name``/``timestamp``/``nonce``/``auth``) is
# added by :func:`sign_response`, which the server entry point calls last.
def ok_content(result: Any) -> list[Node]:
    return [Node("status", ["ok"]), Node("result", [result])]


def block_content(block: Node) -> list[Node]:
    return [Node("status", ["ok"]), block]


def error_content(code: str, message: str) -> list[Node]:
    error = Node("error", children=[Node("code", [code]), Node("message", [message])])
    return [Node("status", ["failure"]), error]


def capabilities_content() -> list[Node]:
    actions = Node("actions", children=[Node(k, [v]) for k, v in ACTIONS.items()])
    values = Node("values", children=[Node(k, [v]) for k, v in VARIABLES.items()])
    return [Node("status", ["ok"]), actions, values]


def sign_response(
    content_nodes: list[Node],
    *,
    secret: str,
    hostname: str,
    req_id: str | None = None,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> str:
    """Wrap response ``content_nodes`` in a signed v2 envelope.

    Every response carries the agent's own ``name`` and is signed with that
    agent's per-host key, so the panel both learns the hostname (discovery) and
    can confirm it is talking to the agent it expected.
    """
    nodes = [Node("v", [PROTOCOL_VERSION])]
    if req_id is not None:
        nodes.append(Node("id", [req_id]))
    nodes.append(Node("name", [hostname]))
    nodes.append(
        Node("timestamp", [agent_auth.now_timestamp() if timestamp is None else timestamp])
    )
    nodes.append(Node("nonce", [agent_auth.make_nonce() if nonce is None else nonce]))
    nodes.extend(content_nodes)
    nodes.append(_auth_node(nodes, secret, hostname))
    return serialize(nodes)


@dataclass
class Response:
    """A parsed, authenticated response, for clients."""

    version: int | None
    id: str | None
    status: str
    result: Any = None
    error_code: str | None = None
    error_message: str | None = None
    settings: dict[str, Any] | None = None
    name: str | None = None
    timestamp: int | None = None
    nonce: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def text(self) -> str:
        """A human-readable one-liner for CLI/panel display."""
        if self.ok:
            if self.settings is not None:
                return "ok"
            return "" if self.result is None else str(self.result)
        return f"{self.error_code}: {self.error_message}"


def parse_response(
    body: str,
    *,
    secret: str,
    expected_name: str | None = None,
    now: int | None = None,
) -> Response:
    """Parse and authenticate a response body received by a client.

    The response signature is verified with the key derived from the ``name``
    the agent reports.  When ``expected_name`` is given (every request after
    discovery), the reported name must match it, defeating attempts to pass off
    one PC's signed response as another's.
    """
    nodes = parse(body)
    by_name = {node.name: node for node in nodes if node.name != "auth"}

    version = by_name["v"].arg if "v" in by_name else None
    req_id = by_name["id"].arg if "id" in by_name else None
    if req_id is not None:
        req_id = str(req_id)

    if version != PROTOCOL_VERSION:
        raise ProtocolError(
            UNSUPPORTED_VERSION,
            f"protocol version {version!r} is not supported",
            req_id,
        )

    name = verify_frame(nodes, secret, req_id=req_id, now=now)
    if expected_name is not None and name != expected_name:
        raise ProtocolError(
            AUTHENTICATION_FAILED,
            "response came from an unexpected agent",
            req_id,
        )

    status = by_name["status"].arg if "status" in by_name else "failure"

    error_code = error_message = None
    if "error" in by_name:
        err = by_name["error"].child_map()
        error_code = err.get("code")
        error_message = err.get("message")

    settings = None
    if "settings" in by_name:
        settings = by_name["settings"].child_map()

    result = by_name["result"].arg if "result" in by_name else None
    return Response(
        version=version,
        id=req_id,
        status=str(status),
        result=result,
        error_code=error_code,
        error_message=error_message,
        settings=settings,
        name=name,
        timestamp=by_name["timestamp"].arg if "timestamp" in by_name else None,
        nonce=by_name["nonce"].arg if "nonce" in by_name else None,
    )


# ===========================================================================
# Server-side dispatch
# ===========================================================================
def _format_time(value: Any) -> str | None:
    """Render a datetime.time as HH:MM, passing through None."""
    if value is None:
        return None
    return f"{value.hour:02d}:{value.minute:02d}"


def _parse_hhmm(raw: Any, req_id: str | None) -> tuple[int, int]:
    try:
        hour_str, minute_str = str(raw).split(":")
        hour, minute = int(hour_str), int(minute_str)
    except (ValueError, AttributeError):
        raise ProtocolError(INVALID_VALUE, "time must be HH:MM", req_id)
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ProtocolError(INVALID_VALUE, "time out of range (00:00–23:59)", req_id)
    return hour, minute


def _parse_int(raw: Any, req_id: str | None) -> int:
    if isinstance(raw, bool):  # bool is an int subclass; reject it explicitly
        raise ProtocolError(INVALID_VALUE, "expected a number", req_id)
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw))
    except ValueError:
        raise ProtocolError(INVALID_VALUE, "expected a number", req_id)


def _parse_bool(raw: Any, req_id: str | None) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in ("true", "yes", "1"):
        return True
    if text in ("false", "no", "0"):
        return False
    raise ProtocolError(INVALID_VALUE, "expected a boolean", req_id)


def _read_variable(control: Any, var: str) -> Any:
    if var == "name":
        return control.platform.get_hostname()
    if var == "status":
        return "LOCKED" if control.check_if_locked() else "UNLOCKED"
    if var == "current_user":
        return control.current_user
    if var == "daily_limit":
        return control.daily.allowance
    if var == "bed_time":
        return _format_time(control.daily.bed_time)
    if var == "manual_lock":
        return bool(control.runtime.manual_lock_active)
    if var == "wake_time":
        return _format_time(control.daily.wake_time)
    if var == "cumulative_extension":
        return int(control.runtime.cumulative_extension_seconds)
    if var == "accumulated_seconds":
        return int(control.runtime.accumulated_seconds)
    if var == "time_remaining":
        remaining = control.get_time_remaining()
        return None if remaining is None else round(remaining)
    raise ProtocolError(UNKNOWN_VARIABLE, f"unknown variable: {var}")


def _do_get(control: Any, req: Request) -> list[Node]:
    if req.var == "settings":
        children = [Node(name, [_read_variable(control, name)]) for name in VARIABLES]
        return block_content(Node("settings", children=children))
    return ok_content(_read_variable(control, req.var))  # type: ignore[arg-type]


def _do_set(control: Any, req: Request) -> list[Node]:
    var, val, req_id = req.var, req.val, req.id
    if var not in WRITABLE_VARIABLES:
        raise ProtocolError(FORBIDDEN, f"{var} is read-only", req_id)

    if var == "daily_limit":
        minutes = _parse_int(val, req_id)
        if not (MIN_DAILY_LIMIT <= minutes <= MAX_DAILY_LIMIT):
            raise ProtocolError(
                INVALID_VALUE,
                f"minutes must be between {MIN_DAILY_LIMIT} and {MAX_DAILY_LIMIT}",
                req_id,
            )
        control.set_daily_allowance(minutes)
        result: Any = minutes
    elif var == "bed_time":
        hour, minute = _parse_hhmm(val, req_id)
        control.set_bed_time(hour, minute)
        result = f"{hour:02d}:{minute:02d}"
    elif var == "wake_time":
        hour, minute = _parse_hhmm(val, req_id)
        control.set_wake_time(hour, minute)
        result = f"{hour:02d}:{minute:02d}"
    else:  # manual_lock
        engaged = _parse_bool(val, req_id)
        control.runtime.manual_lock_active = engaged
        if engaged:
            control.lock_pc()
        result = engaged

    control.save_state()
    return ok_content(result)


def _do_clear(control: Any, req: Request) -> list[Node]:
    var, req_id = req.var, req.id
    if var not in CLEARABLE_VARIABLES:
        raise ProtocolError(FORBIDDEN, f"{var} cannot be cleared", req_id)

    if var == "daily_limit":
        control.set_daily_allowance(None)
    elif var == "bed_time":
        control.clear_bed_time()
        control.warnings_sent.clear()
    elif var == "cumulative_extension":
        control.clear_extensions()
    else:  # manual_lock
        control.runtime.manual_lock_active = False

    control.save_state()
    return ok_content("cleared")


def _do_extend(control: Any, req: Request) -> list[Node]:
    minutes = _parse_int(req.val, req.id)
    control.extend_time(minutes)
    control.save_state()
    return ok_content(minutes)


def _do_message(control: Any, req: Request) -> list[Node]:
    control.show_message(str(req.val))
    return ok_content("message sent")


def _do_shutdown(control: Any, req: Request) -> list[Node]:
    seconds = DEFAULT_SHUTDOWN_SECONDS if req.val is None else _parse_int(req.val, req.id)
    if seconds < 0:
        raise ProtocolError(INVALID_VALUE, "seconds must not be negative", req.id)
    control.shutdown_pc(seconds)
    return ok_content(seconds)


def dispatch(control: Any, req: Request) -> list[Node]:
    """Execute a validated request against ``control`` and return content nodes.

    The returned nodes are the response body's ``status`` plus payload; the
    signed v2 envelope is added by :func:`handle_request`.
    """
    if req.action == "list_capabilities":
        return capabilities_content()
    if req.action == "get":
        return _do_get(control, req)
    if req.action == "set":
        return _do_set(control, req)
    if req.action == "clear":
        return _do_clear(control, req)
    if req.action == "extend":
        return _do_extend(control, req)
    if req.action == "message":
        return _do_message(control, req)
    if req.action == "shutdown":
        return _do_shutdown(control, req)
    if req.action == "lock":
        control.runtime.manual_lock_active = True
        control.lock_pc()
        control.save_state()
        return ok_content("locked")
    if req.action == "unlock":
        control.runtime.manual_lock_active = False
        control.save_state()
        return ok_content("unlocked")
    raise ProtocolError(UNKNOWN_ACTION, f"unknown action: {req.action}", req.id)


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
    try:
        req = parse_request(body, secret=secret, hostname=hostname, now=now)
        req_id = req.id
        content = dispatch(control, req)
    except ProtocolError as exc:
        content = error_content(exc.code, exc.message)
        req_id = exc.req_id or req_id
    except Exception as exc:  # noqa: BLE001 - defensive catch-all per design
        content = error_content(INTERNAL_ERROR, str(exc))
    return sign_response(content, secret=secret, hostname=hostname, req_id=req_id)

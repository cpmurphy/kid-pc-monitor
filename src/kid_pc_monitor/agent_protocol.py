"""Structured request/response protocol for kid PC agents (version 1).

The wire format is a length-prefixed body written in a small subset of
`KDL <https://kdl.dev/spec>`_.  Each line is a node: a bare identifier name
followed by a single value, e.g. ``action set``.  Blocks (``{ ... }``) carry
nested nodes, used for ``error``, ``settings``, and ``list_capabilities``
responses.  The subset deliberately omits comments, type annotations, floating
point numbers, and KDL's multi-line string syntax.

The previous ad-hoc line protocol (``GET_STATUS`` etc.) is treated as version
zero; both live side by side during the transition.  See
``docs/agent-protocol.md`` for the full design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 1

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
    - ``NOT_FRAME``: the head is not a numeric length prefix (legacy command).
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
# Requests
# ===========================================================================
@dataclass
class Request:
    version: int
    id: str | None
    action: str
    var: str | None = None
    val: Any = None


def build_request(
    action: str,
    *,
    var: str | None = None,
    val: Any = None,
    req_id: str | None = None,
) -> str:
    """Build a request body for a client to send."""
    nodes = [Node("v", [PROTOCOL_VERSION])]
    if req_id is not None:
        nodes.append(Node("id", [req_id]))
    nodes.append(Node("action", [action]))
    if var is not None:
        nodes.append(Node("var", [var]))
    if val is not None:
        nodes.append(Node("val", [val]))
    return serialize(nodes)


def parse_request(body: str) -> Request:
    """Parse and structurally validate a request body.

    Raises :class:`ProtocolError` for malformed requests, unsupported versions,
    and unknown actions/variables.  Value-level checks happen in :func:`dispatch`.
    """
    try:
        nodes = parse(body)
    except ProtocolError:
        raise ProtocolError(INVALID_REQUEST, "could not parse request")

    fields = {node.name: node.arg for node in nodes}
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

    action = fields.get("action")
    if action not in ACTIONS:
        raise ProtocolError(UNKNOWN_ACTION, f"unknown action: {action!r}", req_id)

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

    return Request(PROTOCOL_VERSION, req_id, action, var, val)


# ===========================================================================
# Responses
# ===========================================================================
def _envelope(req_id: str | None, status: str, *extra: Node) -> str:
    nodes = [Node("v", [PROTOCOL_VERSION])]
    if req_id is not None:
        nodes.append(Node("id", [req_id]))
    nodes.append(Node("status", [status]))
    nodes.extend(extra)
    return serialize(nodes)


def ok_response(req_id: str | None, result: Any) -> str:
    return _envelope(req_id, "ok", Node("result", [result]))


def block_response(req_id: str | None, block: Node) -> str:
    return _envelope(req_id, "ok", block)


def error_response(req_id: str | None, code: str, message: str) -> str:
    error = Node("error", children=[Node("code", [code]), Node("message", [message])])
    return _envelope(req_id, "failure", error)


def capabilities_response(req_id: str | None) -> str:
    actions = Node("actions", children=[Node(k, [v]) for k, v in ACTIONS.items()])
    values = Node("values", children=[Node(k, [v]) for k, v in VARIABLES.items()])
    return _envelope(req_id, "ok", actions, values)


@dataclass
class Response:
    """A parsed response, for clients."""

    version: int | None
    id: str | None
    status: str
    result: Any = None
    error_code: str | None = None
    error_message: str | None = None
    settings: dict[str, Any] | None = None

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


def parse_response(body: str) -> Response:
    """Parse a response body received by a client."""
    nodes = parse(body)
    by_name = {node.name: node for node in nodes}

    version = by_name["v"].arg if "v" in by_name else None
    req_id = by_name["id"].arg if "id" in by_name else None
    if req_id is not None:
        req_id = str(req_id)
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


def _do_get(control: Any, req: Request) -> str:
    if req.var == "settings":
        children = [Node(name, [_read_variable(control, name)]) for name in VARIABLES]
        return block_response(req.id, Node("settings", children=children))
    return ok_response(req.id, _read_variable(control, req.var))  # type: ignore[arg-type]


def _do_set(control: Any, req: Request) -> str:
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
    return ok_response(req_id, result)


def _do_clear(control: Any, req: Request) -> str:
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
    return ok_response(req_id, "cleared")


def _do_extend(control: Any, req: Request) -> str:
    minutes = _parse_int(req.val, req.id)
    control.extend_time(minutes)
    control.save_state()
    return ok_response(req.id, minutes)


def _do_message(control: Any, req: Request) -> str:
    control.show_message(str(req.val))
    return ok_response(req.id, "message sent")


def _do_shutdown(control: Any, req: Request) -> str:
    seconds = DEFAULT_SHUTDOWN_SECONDS if req.val is None else _parse_int(req.val, req.id)
    if seconds < 0:
        raise ProtocolError(INVALID_VALUE, "seconds must not be negative", req.id)
    control.shutdown_pc(seconds)
    return ok_response(req.id, seconds)


def dispatch(control: Any, req: Request) -> str:
    """Execute a validated request against ``control`` and return a response body."""
    if req.action == "list_capabilities":
        return capabilities_response(req.id)
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
        return ok_response(req.id, "locked")
    if req.action == "unlock":
        control.runtime.manual_lock_active = False
        control.save_state()
        return ok_response(req.id, "unlocked")
    raise ProtocolError(UNKNOWN_ACTION, f"unknown action: {req.action}", req.id)


def handle_request(control: Any, body: str) -> str:
    """Top-level server entry: parse, dispatch, and serialize, never raising.

    Any :class:`ProtocolError` becomes a failure response; unexpected
    exceptions become an ``internal_error`` response.
    """
    req_id: str | None = None
    try:
        req = parse_request(body)
        req_id = req.id
        return dispatch(control, req)
    except ProtocolError as exc:
        return error_response(exc.req_id or req_id, exc.code, exc.message)
    except Exception as exc:  # noqa: BLE001 - defensive catch-all per design
        return error_response(req_id, INTERNAL_ERROR, str(exc))

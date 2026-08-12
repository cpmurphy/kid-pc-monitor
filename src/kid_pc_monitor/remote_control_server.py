"""Request handling for the kid agent (used by reverse TCP sessions)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kid_pc_monitor import agent_protocol, request_dispatcher

if TYPE_CHECKING:
    from kid_pc_monitor.pc_time_control import PCTimeControl


def handle_request(
    control: PCTimeControl,
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
    response_version = agent_protocol.peek_version(body)
    try:
        req = agent_protocol.parse_request(body, secret=secret, hostname=hostname, now=now)
        req_id = req.id
        response_version = req.version
        content = request_dispatcher.dispatch(control, req)
    except agent_protocol.ProtocolError as exc:
        content = agent_protocol.error_content(exc.code, exc.message)
        req_id = exc.req_id or req_id
    except Exception as exc:  # noqa: BLE001 - defensive catch-all per design
        content = agent_protocol.error_content(agent_protocol.INTERNAL_ERROR, str(exc))
    return agent_protocol.sign_response(
        content,
        secret=secret,
        hostname=hostname,
        req_id=req_id,
        version=response_version,
    )

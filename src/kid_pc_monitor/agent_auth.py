"""HMAC-SHA256 authentication primitives for protocol v2.

These helpers are deliberately free of any dependency on
:mod:`kid_pc_monitor.agent_protocol` so the protocol layer can import them
without creating a cycle.  The protocol layer is responsible for building the
canonical signing string (the serialized frame minus its ``auth`` block); this
module only signs and verifies that string and derives the per-agent key.

See the "Security" section of ``docs/agent-protocol.md`` for the full design.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

# The only signature algorithm v2 defines.
ALGORITHM = "hmac-sha256"

# Identifies which shared secret produced a signature.  A single shared secret
# is used today, so this is a constant.
DEFAULT_KEY_ID = "kid-pc-monitor-shared-secret"

# A frame whose timestamp is further than this from the recipient's clock is
# rejected as stale.  Wide enough to tolerate NTP drift, far too narrow to
# replay yesterday's captured command.
TIMESTAMP_WINDOW_SECONDS = 60

# Nonces carry at least 16 bytes of randomness, hex-encoded (32 hex chars).
NONCE_BYTES = 16
NONCE_MIN_HEX_CHARS = NONCE_BYTES * 2


def derive_key(shared_secret: str, name: str | None) -> bytes:
    """Return the HMAC signing key for a frame addressed to ``name``.

    Read-only discovery frames carry no ``name`` and are signed with the raw
    shared secret.  Every destination-specific frame mixes the target agent's
    hostname into the key as ``HMAC-SHA256(shared_secret, name)`` so that a
    signature valid for one PC will not verify on another, even though both
    PCs share the same raw secret.
    """
    secret_bytes = shared_secret.encode("utf-8")
    if name is None:
        return secret_bytes
    return hmac.new(secret_bytes, name.encode("utf-8"), hashlib.sha256).digest()


def compute_signature(key: bytes, canonical: str) -> str:
    """Return ``base64url(HMAC-SHA256(key, canonical_utf8_bytes))``."""
    digest = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def verify_signature(key: bytes, canonical: str, signature: str) -> bool:
    """Constant-time check that ``signature`` matches ``canonical`` under ``key``."""
    expected = compute_signature(key, canonical)
    return hmac.compare_digest(expected, signature)


def make_nonce() -> str:
    """Return a fresh hex nonce with :data:`NONCE_BYTES` of randomness."""
    return secrets.token_hex(NONCE_BYTES)


def is_valid_nonce(nonce: object) -> bool:
    """True when ``nonce`` is a hex string of at least the minimum length."""
    if not isinstance(nonce, str) or len(nonce) < NONCE_MIN_HEX_CHARS:
        return False
    try:
        int(nonce, 16)
    except ValueError:
        return False
    return True


def now_timestamp() -> int:
    """Current Unix time in whole seconds."""
    return int(time.time())


def timestamp_in_window(
    timestamp: int,
    *,
    now: int | None = None,
    window: int = TIMESTAMP_WINDOW_SECONDS,
) -> bool:
    """True when ``timestamp`` is within ``window`` seconds of ``now``."""
    current = now_timestamp() if now is None else now
    return abs(current - timestamp) <= window

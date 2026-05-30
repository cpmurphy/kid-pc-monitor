"""Encrypted-at-rest secret storage for agent and web panel.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256).  The encryption
key is derived from a hardcoded bootstrap key which can be overridden via the
``KID_PC_MONITOR_SECRET_KEY`` environment variable.  Each named secret is stored
as a separate ``<name>.enc`` file.

Storage location
----------------
A secret may be written either by an installer running as an administrator or
by the agent/panel running as an ordinary user, and it must be readable across
those accounts.  In the "mode 2" agent deployment the installer runs as an
admin while the agent runs in the child's non-admin session, so a per-user
config directory is not enough — the admin's copy would be invisible to the
child.

To handle this, secrets are searched and stored in this priority order:

1. ``$KID_PC_MONITOR_SECRETS_DIR`` if set (explicit override, used by tests and
   custom deployments).
2. A machine-wide directory readable by every account on the PC
   (``%ProgramData%\\KidPCMonitor\\secrets`` on Windows,
   ``/etc/kid-pc-monitor/secrets`` elsewhere).  The installer writes here.
3. The per-user config directory (back-compat and single-user installs).

``save_secret`` writes to the first location it can create/write; ``load_secret``
returns the first location that holds a decryptable secret.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet

from kid_pc_monitor.paths import config_dir

_BOOTSTRAP_KEY = b"kid-pc-monitor-v3-shared-secret-kdf-2026"

_SECRETS_DIR_NAME = "secrets"

# Explicit override; when set it is the sole secrets directory.
_SECRETS_DIR_ENV = "KID_PC_MONITOR_SECRETS_DIR"


def _derive_key() -> bytes:
    """Derive a 32-byte Fernet key from the bootstrap key + env override."""
    raw = os.environ.get("KID_PC_MONITOR_SECRET_KEY", "").strip()
    material = raw.encode("utf-8") if raw else _BOOTSTRAP_KEY
    derived = hashlib.pbkdf2_hmac("sha256", material, b"kpm-fernet-salt", 600_000, dklen=32)
    return base64.urlsafe_b64encode(derived)


def _machine_secrets_dir() -> Path:
    """Machine-wide secrets directory readable by every account on this PC."""
    if sys.platform == "win32":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "KidPCMonitor"
    else:
        base = Path("/etc/kid-pc-monitor")
    return base / _SECRETS_DIR_NAME


def _user_secrets_dir() -> Path:
    return config_dir() / _SECRETS_DIR_NAME


def secrets_dirs() -> list[Path]:
    """Candidate secrets directories, highest priority first (deduplicated)."""
    candidates: list[Path] = []
    override = os.environ.get(_SECRETS_DIR_ENV, "").strip()
    if override:
        # An explicit override is authoritative: do not silently fall back to
        # other locations, which keeps tests and custom layouts isolated.
        return [Path(override)]
    candidates.append(_machine_secrets_dir())
    candidates.append(_user_secrets_dir())

    seen: set[str] = set()
    unique: list[Path] = []
    for directory in candidates:
        key = str(directory)
        if key not in seen:
            seen.add(key)
            unique.append(directory)
    return unique


def _secrets_dir() -> Path:
    """The preferred (highest-priority) secrets directory."""
    return secrets_dirs()[0]


def _secret_path(name: str) -> Path:
    return _secrets_dir() / f"{name}.enc"


def save_secret(name: str, value: str) -> Path:
    """Encrypt *value* and write it atomically to the first writable location.

    Returns the path written.  Raises the last OSError if no candidate
    directory could be written (e.g. a non-admin user with no per-user dir).
    """
    fernet = Fernet(_derive_key())
    token = fernet.encrypt(value.encode("utf-8"))

    last_error: OSError | None = None
    for directory in secrets_dirs():
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / f"{name}.enc"
            tmp = path.with_suffix(".enc.tmp")
            tmp.write_bytes(token)
            os.replace(tmp, path)
            return path
        except OSError as exc:
            last_error = exc
            continue

    raise last_error if last_error is not None else OSError("no writable secrets directory")


def load_secret(name: str) -> str | None:
    """Decrypt and return the named secret, or None if it is not found."""
    fernet: Fernet | None = None
    for directory in secrets_dirs():
        path = directory / f"{name}.enc"
        if not path.is_file():
            continue
        try:
            if fernet is None:
                fernet = Fernet(_derive_key())
            return fernet.decrypt(path.read_bytes()).decode("utf-8")
        except Exception:
            continue
    return None

def delete_secret(name: str) -> bool:
    """Remove the named secret from every location.  True if any existed."""
    removed = False
    for directory in secrets_dirs():
        path = directory / f"{name}.enc"
        if path.is_file():
            try:
                path.unlink()
                removed = True
            except OSError:
                continue
    return removed


def generate_secret(length: int = 32) -> str:
    """Return a cryptographically random hex secret (64 chars for the default 32 bytes)."""
    return secrets.token_hex(length)

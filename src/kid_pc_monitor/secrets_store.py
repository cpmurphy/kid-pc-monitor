"""Encrypted-at-rest secret storage for agent and web panel.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256).  The encryption
key is derived from a hardcoded bootstrap key which can be overridden via the
``KID_PC_MONITOR_SECRET_KEY`` environment variable.  Each named secret is stored
as a separate file under the user config directory.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

from kid_pc_monitor.paths import config_dir

_BOOTSTRAP_KEY = b"kid-pc-monitor-v3-shared-secret-kdf-2026"

_SECRETS_DIR_NAME = "secrets"


def _derive_key() -> bytes:
    """Derive a 32-byte Fernet key from the bootstrap key + env override."""
    raw = os.environ.get("KID_PC_MONITOR_SECRET_KEY", "").strip()
    material = raw.encode("utf-8") if raw else _BOOTSTRAP_KEY
    derived = hashlib.pbkdf2_hmac("sha256", material, b"kpm-fernet-salt", 600_000, dklen=32)
    return base64.urlsafe_b64encode(derived)


def _secrets_dir() -> Path:
    return config_dir() / _SECRETS_DIR_NAME


def _secret_path(name: str) -> Path:
    return _secrets_dir() / f"{name}.enc"


def save_secret(name: str, value: str) -> None:
    """Encrypt *value* and write it to disk atomically."""
    fernet = Fernet(_derive_key())
    token = fernet.encrypt(value.encode("utf-8"))
    path = _secret_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".enc.tmp")
    tmp.write_bytes(token)
    os.replace(tmp, path)


def load_secret(name: str) -> str | None:
    """Decrypt and return the named secret, or None if it does not exist."""
    path = _secret_path(name)
    if not path.is_file():
        return None
    try:
        fernet = Fernet(_derive_key())
        return fernet.decrypt(path.read_bytes()).decode("utf-8")
    except Exception:
        return None


def delete_secret(name: str) -> bool:
    """Remove the named secret file.  Returns True if it existed."""
    path = _secret_path(name)
    if not path.is_file():
        return False
    path.unlink()
    return True


def generate_secret(length: int = 32) -> str:
    """Return a cryptographically random hex secret (64 chars for the default 32 bytes)."""
    return secrets.token_hex(length)
"""Package and user-writable config paths."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def package_dir() -> Path:
    """Directory containing installed package modules and templates."""
    return Path(__file__).resolve().parent


def config_dir() -> Path:
    """User-writable directory for web panel auth and other local settings."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "kid-pc-monitor"


def tls_dir() -> Path:
    """Directory for optional web panel TLS certificate and key."""
    return config_dir() / "tls"


def resolve_tls_cert_paths() -> tuple[str, str] | None:
    """Return (cert_path, key_path) when TLS files are configured and readable."""
    cert_env = os.environ.get("KID_PC_MONITOR_SSL_CERT")
    key_env = os.environ.get("KID_PC_MONITOR_SSL_KEY")
    if cert_env and key_env:
        cert_path = Path(cert_env)
        key_path = Path(key_env)
    else:
        cert_path = tls_dir() / "cert.pem"
        key_path = tls_dir() / "key.pem"

    if not cert_path.is_file() or not key_path.is_file():
        return None
    try:
        with cert_path.open():
            pass
        with key_path.open():
            pass
    except OSError:
        return None
    return str(cert_path), str(key_path)


def template_dir() -> Path:
    return package_dir() / "templates"


def static_dir() -> Path:
    return package_dir() / "static"

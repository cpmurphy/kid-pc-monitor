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


def template_dir() -> Path:
    return package_dir() / "templates"

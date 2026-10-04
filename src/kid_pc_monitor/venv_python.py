"""Detect a virtualenv whose interpreter no longer matches pyvenv.cfg."""

from __future__ import annotations

import sys
from pathlib import Path

# install_web_panel_linux.sh exits immediately when Python returns this status.
VENV_PYTHON_MISMATCH_STATUS = 2


def ensure_venv_python_matches() -> None:
    """Exit when this venv's pyvenv.cfg Python is not the one running.

    After ``/usr/bin/python3`` moves to a new feature release, ``sys.prefix``
    still points at the venv but its site-packages are not on the path.
    """
    created = _pyvenv_python(Path(sys.prefix) / "pyvenv.cfg")
    running = sys.version_info[:2]
    if created is None or created == running:
        return
    print(
        f"This venv was created with Python {created[0]}.{created[1]} but is running "
        f"Python {running[0]}.{running[1]}.\n"
        "Recreate it and reinstall packages with the venv Python:\n"
        "  python3 -m venv venv\n"
        "  ./venv/bin/python3 -m pip install -r requirements.txt\n"
        "  ./venv/bin/python3 -m pip install -e .",
        file=sys.stderr,
    )
    raise SystemExit(VENV_PYTHON_MISMATCH_STATUS)


def _pyvenv_python(cfg_path: Path) -> tuple[int, int] | None:
    try:
        lines = cfg_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep or key.strip() != "version":
            continue
        parts = value.strip().split(".")
        if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
            return None
        return int(parts[0]), int(parts[1])
    return None

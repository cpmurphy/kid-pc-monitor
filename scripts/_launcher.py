"""Shared bootstrap for scripts/run_*.py launchers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"


def repo_venv_python() -> Path | None:
    """Return the repo venv interpreter if ./venv or ./.venv exists."""
    for name in ("venv", ".venv"):
        venv_python = _REPO_ROOT / name / "bin" / "python3"
        if venv_python.is_file():
            return venv_python
    return None


def use_repo_venv_if_available() -> None:
    """Re-exec with the repo venv interpreter when ./venv or ./.venv exists."""
    venv_python = repo_venv_python()
    if venv_python is None:
        return

    current = os.path.normpath(sys.executable)
    # Do not use .resolve(): venv/bin/python3 often symlinks to system
    # python, but still loads this venv's site-packages.
    if current == os.path.normpath(str(venv_python)):
        return
    os.execv(venv_python, [str(venv_python), *sys.argv])


def ensure_src_on_path() -> None:
    src = str(_SRC)
    if src not in sys.path:
        sys.path.insert(0, src)


def hint_for_missing_venv() -> None:
    script_name = Path(sys.argv[0]).name
    print(
        "No Python virtual environment found in this repo.\n\n"
        "On Debian, Ubuntu, and many other Linux distributions, system Python "
        "blocks `pip install` (externally-managed-environment). Create a venv "
        "before installing dependencies:\n\n"
        f"  cd {_REPO_ROOT}\n"
        "  python3 -m venv venv\n"
        "  # If that fails: sudo apt install python3-venv python3-pip\n"
        f"  ./venv/bin/python3 -m pip install -r requirements.txt\n"
        f"  ./venv/bin/python3 -m pip install -e .\n\n"
        "Then run:\n"
        f"  ./scripts/{script_name}\n"
        f"  # or: ./venv/bin/python3 scripts/{script_name}",
        file=sys.stderr,
    )


def hint_for_missing_dependency(exc: ModuleNotFoundError) -> None:
    if repo_venv_python() is None:
        hint_for_missing_venv()
        return

    script_name = Path(sys.argv[0]).name
    venv_python = _REPO_ROOT / "venv" / "bin" / "python3"
    print(
        f"Missing dependency: {exc.name}\n\n"
        "Install project dependencies in the repo venv, then retry:\n"
        f"  {venv_python} -m pip install -r requirements.txt\n"
        f"  {venv_python} -m pip install -e .\n\n"
        "Or run explicitly with the venv interpreter:\n"
        f"  {venv_python} scripts/{script_name}",
        file=sys.stderr,
    )

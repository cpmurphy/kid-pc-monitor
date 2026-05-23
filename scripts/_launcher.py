"""Shared bootstrap for scripts/run_*.py launchers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"


def use_repo_venv_if_available() -> None:
    """Re-exec with the repo venv interpreter when ./venv or ./.venv exists."""
    current = os.path.normpath(sys.executable)
    for name in ("venv", ".venv"):
        venv_python = _REPO_ROOT / name / "bin" / "python3"
        if not venv_python.is_file():
            continue
        # Do not use .resolve(): venv/bin/python3 often symlinks to system
        # python, but still loads this venv's site-packages.
        if current == os.path.normpath(str(venv_python)):
            return
        os.execv(venv_python, [str(venv_python), *sys.argv])


def ensure_src_on_path() -> None:
    src = str(_SRC)
    if src not in sys.path:
        sys.path.insert(0, src)


def hint_for_missing_dependency(exc: ModuleNotFoundError) -> None:
    print(
        f"Missing dependency: {exc.name}\n\n"
        "Install project dependencies in the repo venv, then retry:\n"
        f"  {_REPO_ROOT / 'venv' / 'bin' / 'python3'} -m pip install -r requirements.txt\n"
        f"  {_REPO_ROOT / 'venv' / 'bin' / 'python3'} -m pip install -e .\n\n"
        "Or run explicitly with the venv interpreter:\n"
        f"  {_REPO_ROOT / 'venv' / 'bin' / 'python3'} {Path(sys.argv[0]).name}",
        file=sys.stderr,
    )

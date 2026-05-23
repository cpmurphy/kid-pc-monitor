#!/usr/bin/env python3
"""Run the Kid PC Monitor agent from a git checkout."""

import sys
from pathlib import Path

_scripts_dir = Path(__file__).resolve().parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from _launcher import ensure_src_on_path, hint_for_missing_dependency, use_repo_venv_if_available

use_repo_venv_if_available()
ensure_src_on_path()

try:
    from kid_pc_monitor.pc_control import main
except ModuleNotFoundError as exc:
    hint_for_missing_dependency(exc)
    raise SystemExit(1) from exc

if __name__ == "__main__":
    raise SystemExit(main())

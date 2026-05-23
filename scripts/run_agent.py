#!/usr/bin/env python3
"""Run the Kid PC Monitor agent from a git checkout (no pip install required)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kid_pc_monitor.pc_control import main

if __name__ == "__main__":
    raise SystemExit(main())

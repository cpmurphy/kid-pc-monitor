"""Runtime bail-out when a venv interpreter does not match pyvenv.cfg."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from kid_pc_monitor.venv_python import VENV_PYTHON_MISMATCH_STATUS, ensure_venv_python_matches


class VenvPythonTests(unittest.TestCase):
    def test_mismatch_tells_user_to_recreate_venv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp)
            other = (sys.version_info[0], sys.version_info[1] + 1)
            (prefix / "pyvenv.cfg").write_text(
                f"home = /usr/bin\nversion = {other[0]}.{other[1]}.0\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "prefix", str(prefix)),
                redirect_stderr(stderr),
                self.assertRaises(SystemExit) as raised,
            ):
                ensure_venv_python_matches()

        self.assertEqual(raised.exception.code, VENV_PYTHON_MISMATCH_STATUS)
        message = stderr.getvalue()
        running = f"{sys.version_info[0]}.{sys.version_info[1]}"
        other = (sys.version_info[0], sys.version_info[1] + 1)
        self.assertIn(
            f"created with Python {other[0]}.{other[1]} but is running Python {running}",
            message,
        )
        self.assertIn("python3 -m venv venv", message)
        self.assertIn("./venv/bin/python3 -m pip install -r requirements.txt", message)
        self.assertIn("./venv/bin/python3 -m pip install -e .", message)

    def test_same_feature_version_continues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp)
            (prefix / "pyvenv.cfg").write_text(
                f"version = {sys.version_info[0]}.{sys.version_info[1]}.99\n",
                encoding="utf-8",
            )
            with mock.patch.object(sys, "prefix", str(prefix)):
                ensure_venv_python_matches()

    def test_no_pyvenv_cfg_continues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sys, "prefix", tmp):
                ensure_venv_python_matches()


if __name__ == "__main__":
    unittest.main()

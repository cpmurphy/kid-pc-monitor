"""The Linux installer stops when a Python command fails."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "install_web_panel_linux.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class InstallWebPanelLinuxTests(unittest.TestCase):
    def _run_install(
        self, python_status: int
    ) -> tuple[subprocess.CompletedProcess[str], bool, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / "bin"
            venv_bin = root / "venv" / "bin"
            bindir.mkdir()
            venv_bin.mkdir(parents=True)
            _write_executable(
                venv_bin / "python3",
                f"""\
                #!/bin/sh
                exit {python_status}
                """,
            )
            _write_executable(venv_bin / "kid-pc-web-panel", "#!/bin/sh\nexit 0\n")
            log = root / "systemctl.log"
            _write_executable(
                bindir / "systemctl",
                f"""\
                #!/bin/sh
                printf '%s\\n' "$*" >> "{log}"
                exit 0
                """,
            )
            env = os.environ.copy()
            env.pop("PYTHON", None)
            env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; REPO_ROOT="$2"; SRC_DIR="$2/src"; '
                    'UNIT_DIR="$2/unit"; UNIT_PATH="$UNIT_DIR/$UNIT_NAME"; '
                    "cmd_install",
                    "bash",
                    str(_SCRIPT),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            unit_exists = (root / "unit" / "kid-pc-monitor-web-panel.service").exists()
            systemctl_log = log.read_text(encoding="utf-8") if log.exists() else ""
            return completed, unit_exists, systemctl_log

    def test_install_stops_when_python_fails(self) -> None:
        for status in (1, 2):
            with self.subTest(status=status):
                completed, unit_exists, systemctl_log = self._run_install(status)
                self.assertEqual(completed.returncode, status, completed.stderr)
                self.assertFalse(unit_exists)
                self.assertNotIn("enable", systemctl_log)
                self.assertNotIn("restart", systemctl_log)
                self.assertNotIn("Service is enabled", completed.stdout)


if __name__ == "__main__":
    unittest.main()

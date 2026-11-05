"""The Linux installer sets up its own venv and stops when a Python command fails."""

from __future__ import annotations

import hashlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "install_web_panel_linux.sh"

# Real tools the script needs; everything else on PATH is a fake.
_REAL_TOOLS = ("bash", "sh", "env", "dirname", "uname", "mkdir", "seq", "grep", "sleep", "id")
_REAL_TOOLS += ("cat", "rm", "chmod", "cp", "mv", "mktemp", "awk", "sed", "head", "sha256sum")


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _healthy_python(log: Path, secret_status: int = 0) -> str:
    """A venv interpreter that passes the health probe and logs each call."""
    return f"""\
        #!/bin/sh
        printf 'venv-python %s\\n' "$*" >> "{log}"
        case "$*" in
            *prompt_and_store_shared_secret*) exit {secret_status} ;;
            *linux_firewall*) echo "Firewall: checked"; exit 0 ;;
            *get_local_ip*) echo "http://192.0.2.10:5000"; exit 0 ;;
        esac
        exit 0
        """


class _Sandbox:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.bindir = root / "bin"
        self.home = root / "home"
        self.log = root / "calls.log"
        self.bindir.mkdir()
        self.home.mkdir()
        for tool in _REAL_TOOLS:
            real = shutil.which(tool)
            assert real is not None, tool
            (self.bindir / tool).symlink_to(real)
        self.fake(
            "systemctl",
            f"""\
            #!/bin/sh
            printf 'systemctl %s\\n' "$*" >> "{self.log}"
            exit 0
            """,
        )
        self.fake("loginctl", "#!/bin/sh\necho yes\n")
        self.fake("ss", "#!/bin/sh\necho 'LISTEN 0 128 0.0.0.0:5000 0.0.0.0:*'\n")

    def fake(self, name: str, body: str) -> None:
        path = self.bindir / name
        # Never write through a symlink to a real tool.
        if path.is_symlink():
            path.unlink()
        _write_executable(path, body)

    def venv_python(self, body: str, venv: str = "venv") -> None:
        _write_executable(self.root / venv / "bin" / "python3", body)

    def base_python_creating_venv(self) -> None:
        """A system python3 whose `-m venv --clear DIR` creates a healthy venv."""
        healthy = _healthy_python(self.log).replace("'", "'\\''")
        self.fake(
            "python3",
            f"""\
            #!/bin/sh
            printf 'base-python %s\\n' "$*" >> "{self.log}"
            if [ "$1 $2" = "-m venv" ]; then
                mkdir -p "$4/bin"
                printf '%s' '{textwrap.dedent(healthy)}' > "$4/bin/python3"
                chmod +x "$4/bin/python3"
            fi
            exit 0
            """,
        )

    def run_install(self, *args: str, **env_overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": str(self.bindir),
            "HOME": str(self.home),
            "USER": "parent",
            **env_overrides,
        }
        return subprocess.run(
            [
                str(self.bindir / "bash"),
                "-c",
                'source "$1"; REPO_ROOT="$2"; SRC_DIR="$2/src"; '
                'UNIT_DIR="$2/unit"; UNIT_PATH="$UNIT_DIR/$UNIT_NAME"; '
                'cmd_install "${@:3}"',
                "bash",
                str(_SCRIPT),
                str(self.root),
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            stdin=subprocess.DEVNULL,
        )

    @property
    def unit_path(self) -> Path:
        return self.root / "unit" / "kid-pc-monitor-web-panel.service"

    def calls(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""


class InstallWebPanelLinuxTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.box = _Sandbox(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_reuses_healthy_venv_and_installs_package(self) -> None:
        self.box.venv_python(_healthy_python(self.box.log))
        completed = self.box.run_install()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Using virtualenv:", completed.stdout)
        calls = self.box.calls()
        self.assertIn(
            f"-m pip install --quiet --disable-pip-version-check -e {self.box.root}", calls
        )
        self.assertNotIn("base-python", calls)
        unit = self.box.unit_path.read_text(encoding="utf-8")
        self.assertIn(f"ExecStart={self.box.root}/venv/bin/kid-pc-web-panel", unit)
        self.assertIn("systemctl --user enable", calls)
        self.assertIn("systemctl --user restart", calls)
        self.assertIn("Open: http://192.0.2.10:5000", completed.stdout)
        self.assertIn("lingering is on", completed.stdout)
        self.assertIn("linux_firewall --interactive 5000 9998", calls)

    def test_install_stops_when_python_fails(self) -> None:
        for status in (1, 2):
            with self.subTest(status=status):
                self.box.venv_python(_healthy_python(self.box.log, secret_status=status))
                completed = self.box.run_install()
                self.assertEqual(completed.returncode, status, completed.stderr)
                self.assertFalse(self.box.unit_path.exists())
                calls = self.box.calls()
                self.assertNotIn("enable", calls)
                self.assertNotIn("restart", calls)
                self.assertNotIn("Service is enabled", completed.stdout)

    def test_recreates_broken_venv_with_system_python(self) -> None:
        # e.g. /usr/bin/python3 moved to a new release under an existing venv.
        self.box.venv_python("#!/bin/sh\nexit 2\n")
        self.box.base_python_creating_venv()
        completed = self.box.run_install()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("no longer works", completed.stdout)
        self.assertIn(f"base-python -m venv --clear {self.box.root}/venv", self.box.calls())
        self.assertTrue(self.box.unit_path.exists())

    def test_creates_venv_when_none_exists(self) -> None:
        self.box.base_python_creating_venv()
        completed = self.box.run_install()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((self.box.root / "venv" / "bin" / "python3").exists())
        self.assertIn("-m pip install", self.box.calls())

    def test_uses_uv_when_system_python_is_too_old(self) -> None:
        self.box.fake("python3", "#!/bin/sh\nexit 1\n")
        healthy = _healthy_python(self.box.log).replace("'", "'\\''")
        self.box.fake(
            "uv",
            f"""\
            #!/bin/sh
            printf 'uv %s\\n' "$*" >> "{self.box.log}"
            for last; do :; done
            mkdir -p "$last/bin"
            printf '%s' '{textwrap.dedent(healthy)}' > "$last/bin/python3"
            chmod +x "$last/bin/python3"
            """,
        )
        completed = self.box.run_install()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            f"uv venv --clear --seed --python >=3.11 {self.box.root}/venv", self.box.calls()
        )
        self.assertTrue(self.box.unit_path.exists())

    def test_no_python_and_no_uv_without_terminal_explains_and_stops(self) -> None:
        completed = self.box.run_install()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("No usable Python 3.11+", completed.stderr)
        self.assertIn("Install Python 3.11+", completed.stderr)
        self.assertFalse(self.box.unit_path.exists())

    def test_invalid_python_override_stops(self) -> None:
        self.box.fake("old-python", "#!/bin/sh\nexit 1\n")
        completed = self.box.run_install(PYTHON=str(self.box.bindir / "old-python"))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("is not a runnable Python 3.11+", completed.stderr)
        self.assertFalse(self.box.unit_path.exists())

    def test_offers_linger_only_when_disabled(self) -> None:
        self.box.venv_python(_healthy_python(self.box.log))
        self.box.fake("loginctl", "#!/bin/sh\necho no\n")
        completed = self.box.run_install()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("sudo loginctl enable-linger parent", completed.stdout)


def _fake_panel(log: Path, secret_status: int = 0) -> str:
    """A kid-pc-web-panel binary that logs how it is called."""
    return f"""\
        #!/bin/sh
        printf 'panel %s\\n' "$*" >> "{log}"
        case "$1" in
            version) echo v9.9.9 ;;
            set-secret) exit {secret_status} ;;
        esac
        exit 0
        """


class InstallGoWebPanelLinuxTests(unittest.TestCase):
    """install --go: the Go panel binary, no virtualenv."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.box = _Sandbox(Path(self._tmp.name))
        self.box.fake("uname", '#!/bin/sh\ncase "$1" in -m) echo x86_64 ;; *) echo Linux ;; esac\n')
        self.go_bin = (
            self.box.home / ".local" / "share" / "kid-pc-monitor" / "bin" / "kid-pc-web-panel"
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _binary(self, name: str = "built-panel", secret_status: int = 0) -> Path:
        path = self.box.root / name
        _write_executable(path, _fake_panel(self.box.log, secret_status))
        return path

    def _release(self, *, corrupt: bool = False) -> None:
        """A fake curl serving a v9.9.9 release from a local folder."""
        release = self.box.root / "release"
        release.mkdir()
        asset = release / "kid-pc-web-panel-linux-amd64"
        _write_executable(asset, _fake_panel(self.box.log))
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        if corrupt:
            asset.write_text(asset.read_text() + "# tampered\n", encoding="utf-8")
        (release / "SHA256SUMS").write_text(
            f"{'0' * 64}  kid-pc-agent-windows-amd64.exe\n{digest}  kid-pc-web-panel-linux-amd64\n",
            encoding="utf-8",
        )
        (release / "latest.json").write_text(
            '{"tag_name": "v9.9.9", "name": "x"}', encoding="utf-8"
        )
        self.box.fake(
            "curl",
            f"""\
            #!/bin/sh
            out=""; url=""
            while [ $# -gt 0 ]; do
                case "$1" in -o) out="$2"; shift ;; -*) ;; *) url="$1" ;; esac
                shift
            done
            printf 'curl %s\\n' "$url" >> "{self.box.log}"
            case "$url" in
                */repos/cpmurphy/kid-pc-monitor/releases/latest) cp "{release}/latest.json" "$out" ;;
                */cpmurphy/kid-pc-monitor/releases/download/v9.9.9/*) cp "{release}/${{url##*/}}" "$out" ;;
                *) exit 22 ;;
            esac
            """,
        )

    def test_installs_given_binary_without_python(self) -> None:
        completed = self.box.run_install("--go", "--binary", str(self._binary()))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(self.go_bin.is_file())
        self.assertTrue(self.go_bin.stat().st_mode & stat.S_IXUSR)
        unit = self.box.unit_path.read_text(encoding="utf-8")
        self.assertIn(f"ExecStart={self.go_bin} serve", unit)
        self.assertNotIn("PYTHONPATH", unit)
        calls = self.box.calls()
        self.assertIn("panel set-secret", calls)
        self.assertNotIn("venv-python", calls)
        self.assertNotIn("base-python", calls)
        self.assertIn("systemctl --user restart kid-pc-monitor-web-panel.service", calls)
        self.assertIn("Installed:", completed.stdout)
        self.assertIn("v9.9.9", completed.stdout)
        # No system Python here, so the firewall advice is printed instead.
        self.assertIn("inbound TCP 5000 and 9998", completed.stdout)

    def test_missing_binary_stops_before_the_unit(self) -> None:
        completed = self.box.run_install("--go", "--binary", str(self.box.root / "nope"))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Panel binary not found", completed.stderr)
        self.assertFalse(self.box.unit_path.exists())
        self.assertFalse(self.go_bin.exists())

    def test_downloads_release_and_checks_sha256(self) -> None:
        self._release()
        completed = self.box.run_install("--go")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("SHA-256 verified", completed.stdout)
        self.assertIn("releases/download/v9.9.9/kid-pc-web-panel-linux-amd64", self.box.calls())
        self.assertTrue(self.go_bin.is_file())
        self.assertTrue(self.box.unit_path.exists())

    def test_download_with_bad_checksum_keeps_old_binary_and_stops(self) -> None:
        self.go_bin.parent.mkdir(parents=True)
        self.go_bin.write_text("old", encoding="utf-8")
        self._release(corrupt=True)
        completed = self.box.run_install("--go", "--version", "v9.9.9")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match SHA256SUMS", completed.stderr)
        self.assertEqual(self.go_bin.read_text(encoding="utf-8"), "old")
        self.assertFalse(self.box.unit_path.exists())
        leftovers = [p.name for p in self.go_bin.parent.iterdir() if p.name != "kid-pc-web-panel"]
        self.assertEqual(leftovers, [])

    def test_copies_legacy_auth_file_once(self) -> None:
        legacy = self.box.root / "src" / "kid_pc_monitor" / "web_panel_auth.json"
        legacy.parent.mkdir(parents=True)
        legacy.write_text('{"password_hash": "legacy"}', encoding="utf-8")
        canonical = self.box.home / ".config" / "kid-pc-monitor" / "web_panel_auth.json"
        completed = self.box.run_install("--go", "--binary", str(self._binary()))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(canonical.read_text(encoding="utf-8"), '{"password_hash": "legacy"}')
        self.assertEqual(stat.S_IMODE(canonical.stat().st_mode), 0o600)
        canonical.write_text('{"password_hash": "newer"}', encoding="utf-8")
        self.box.run_install("--go", "--binary", str(self._binary()))
        self.assertEqual(canonical.read_text(encoding="utf-8"), '{"password_hash": "newer"}')

    def test_cancelled_secret_does_not_stop_the_install(self) -> None:
        completed = self.box.run_install("--go", "--binary", str(self._binary(secret_status=1)))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Set it later with:", completed.stdout)
        self.assertTrue(self.box.unit_path.exists())

    def test_version_without_go_is_rejected(self) -> None:
        completed = self.box.run_install("--version", "v1")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--version only applies with --go", completed.stderr)


if __name__ == "__main__":
    unittest.main()

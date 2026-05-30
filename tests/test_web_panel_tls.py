"""Tests for optional web panel TLS certificate resolution."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import paths
from kid_pc_monitor import web_panel as wp


class ResolveTlsCertPathsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.base = Path(self._tmpdir.name)
        self.tls_dir = self.base / "tls"
        self.tls_dir.mkdir()
        self.cert_path = self.tls_dir / "cert.pem"
        self.key_path = self.tls_dir / "key.pem"
        self.cert_path.write_text("fake-cert", encoding="utf-8")
        self.key_path.write_text("fake-key", encoding="utf-8")
        self._config_patch = mock.patch.object(paths, "config_dir", return_value=self.base)
        self._config_patch.start()

    def tearDown(self) -> None:
        self._config_patch.stop()
        self._tmpdir.cleanup()

    def test_returns_default_tls_paths_when_files_exist(self) -> None:
        result = paths.resolve_tls_cert_paths()
        self.assertEqual(result, (str(self.cert_path), str(self.key_path)))

    def test_returns_none_when_files_missing(self) -> None:
        self.cert_path.unlink()
        self.assertIsNone(paths.resolve_tls_cert_paths())

    def test_env_vars_override_default_location(self) -> None:
        with tempfile.TemporaryDirectory() as env_tmp:
            env_cert = Path(env_tmp) / "custom-cert.pem"
            env_key = Path(env_tmp) / "custom-key.pem"
            env_cert.write_text("env-cert", encoding="utf-8")
            env_key.write_text("env-key", encoding="utf-8")
            with mock.patch.dict(
                "os.environ",
                {
                    "KID_PC_MONITOR_SSL_CERT": str(env_cert),
                    "KID_PC_MONITOR_SSL_KEY": str(env_key),
                },
                clear=False,
            ):
                result = paths.resolve_tls_cert_paths()
            self.assertEqual(result, (str(env_cert), str(env_key)))

    def test_returns_none_when_env_cert_missing(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "KID_PC_MONITOR_SSL_CERT": str(self.cert_path),
                "KID_PC_MONITOR_SSL_KEY": str(self.base / "missing-key.pem"),
            },
            clear=False,
        ):
            self.assertIsNone(paths.resolve_tls_cert_paths())

    def test_returns_none_when_cert_not_readable(self) -> None:
        self.cert_path.chmod(0o000)
        try:
            self.assertIsNone(paths.resolve_tls_cert_paths())
        finally:
            self.cert_path.chmod(0o644)


class WebPanelMainTlsTests(unittest.TestCase):
    def test_main_passes_ssl_context_when_tls_configured(self) -> None:
        cert = "/tmp/test-cert.pem"
        key = "/tmp/test-key.pem"
        app = wp.create_app()
        with mock.patch.object(wp, "create_app", return_value=app):
            with mock.patch.object(
                wp, "resolve_tls_cert_paths", return_value=(cert, key)
            ):
                with mock.patch.object(app, "run") as mock_run:
                    with mock.patch.dict(
                        "os.environ",
                        {"KID_PC_MONITOR_HOST": "127.0.0.1", "KID_PC_MONITOR_PORT": "5000"},
                        clear=False,
                    ):
                        wp.main()
        mock_run.assert_called_once_with(
            host="127.0.0.1",
            port=5000,
            debug=False,
            ssl_context=(cert, key),
        )

    def test_main_omits_ssl_context_without_tls(self) -> None:
        app = wp.create_app()
        with mock.patch.object(wp, "create_app", return_value=app):
            with mock.patch.object(wp, "resolve_tls_cert_paths", return_value=None):
                with mock.patch.object(app, "run") as mock_run:
                    wp.main()
        mock_run.assert_called_once_with(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    unittest.main()

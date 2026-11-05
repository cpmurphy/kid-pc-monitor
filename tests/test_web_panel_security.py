"""Tests for web panel security hardening (CSRF, redirects, password change)."""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from werkzeug.security import generate_password_hash

from kid_pc_monitor import web_panel as wp


class WebPanelSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self._tmpdir.name) / wp.AUTH_FILE
        self._patches = [
            mock.patch.object(wp, "_auth_path", return_value=self.auth_path),
            mock.patch.object(wp, "_auth_save_path", return_value=self.auth_path),
        ]
        for patch in self._patches:
            patch.start()
        self.app = wp.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        for patch in self._patches:
            patch.stop()
        self._tmpdir.cleanup()

    def _write_auth(self, password: str = "supersecret1") -> str:
        auth = {
            "secret_key": "c" * 32,
            "password_hash": generate_password_hash(password, method="scrypt"),
        }
        self.auth_path.write_text(json.dumps(auth), encoding="utf-8")
        return password

    def _csrf_from_html(self, html: str) -> str:
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        if match:
            return match.group(1)
        match = re.search(r'name="csrf-token" content="([^"]+)"', html)
        assert match is not None, "csrf token not found in page"
        return match.group(1)

    def _get_csrf(self, url: str) -> str:
        response = self.client.get(url)
        return self._csrf_from_html(response.get_data(as_text=True))

    def _login(self, password: str = "supersecret1") -> None:
        csrf = self._get_csrf("/login")
        response = self.client.post(
            "/login",
            data={"password": password, "csrf_token": csrf},
        )
        self.assertEqual(response.status_code, 302)

    def test_login_rejects_external_next(self) -> None:
        password = self._write_auth()
        csrf = self._get_csrf("/login")
        response = self.client.post(
            "/login",
            data={
                "password": password,
                "csrf_token": csrf,
                "next": "https://evil.example/",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")

    def test_login_accepts_relative_next(self) -> None:
        password = self._write_auth()
        csrf = self._get_csrf("/login")
        response = self.client.post(
            "/login",
            data={
                "password": password,
                "csrf_token": csrf,
                "next": "/control/192.168.1.1",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/control/192.168.1.1")

    def test_login_rejects_next_that_browsers_send_off_site(self) -> None:
        password = self._write_auth()
        for target in (
            "//evil.example/",
            "///evil.example/",
            "/\\evil.example/",
            "\\\\evil.example/",
            "/\t/evil.example/",
            "http://localhost/control/x",
            "javascript:alert(1)",
            "control/x",
        ):
            with self.subTest(target=target):
                csrf = self._get_csrf("/login")
                response = self.client.post(
                    "/login",
                    data={"password": password, "csrf_token": csrf, "next": target},
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location, "/")

    def test_is_local_path(self) -> None:
        self.assertTrue(wp.is_local_path("/"))
        self.assertTrue(wp.is_local_path("/usage/kid%20name"))
        self.assertTrue(wp.is_local_path("/control/192.168.1.1?x=//y"))
        self.assertFalse(wp.is_local_path(""))
        self.assertTrue(wp.is_local_path("/usage/kid name"))
        self.assertFalse(wp.is_local_path("/a\nb"))
        self.assertFalse(wp.is_local_path("/a\x00b"))

    def test_post_without_csrf_rejected(self) -> None:
        self._write_auth()
        response = self.client.post(
            "/set-password",
            data={"password": "newpassword1", "password_confirm": "newpassword1"},
        )
        self.assertEqual(response.status_code, 400)

    def test_post_with_csrf_succeeds(self) -> None:
        csrf = self._get_csrf("/set-password")
        response = self.client.post(
            "/set-password",
            data={
                "csrf_token": csrf,
                "password": "newpassword1",
                "password_confirm": "newpassword1",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")

    def test_action_post_with_csrf_header(self) -> None:
        self._write_auth()
        self._login()
        csrf = self._get_csrf("/")
        with mock.patch.object(wp, "_perform_control_action", return_value=(True, "ok")):
            bad = self.client.post(
                "/action",
                json={"ip": "192.168.1.1", "action": "lock"},
            )
            self.assertEqual(bad.status_code, 400)

            good = self.client.post(
                "/action",
                json={"ip": "192.168.1.1", "action": "lock"},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(good.status_code, 200)
            self.assertTrue(good.get_json()["success"])

    def test_change_password_requires_current(self) -> None:
        old_password = self._write_auth("oldpassword1")
        self._login(old_password)
        csrf = self._get_csrf("/set-password")
        response = self.client.post(
            "/set-password",
            data={
                "csrf_token": csrf,
                "current_password": "wrongpassword",
                "password": "newpassword1",
                "password_confirm": "newpassword1",
            },
        )
        self.assertEqual(response.status_code, 200)
        saved = json.loads(self.auth_path.read_text(encoding="utf-8"))
        self.assertTrue(wp._verify_password(saved, old_password))
        self.assertFalse(wp._verify_password(saved, "newpassword1"))

    def test_change_password_with_current(self) -> None:
        old_password = self._write_auth("oldpassword1")
        self._login(old_password)
        csrf = self._get_csrf("/set-password")
        response = self.client.post(
            "/set-password",
            data={
                "csrf_token": csrf,
                "current_password": old_password,
                "password": "newpassword1",
                "password_confirm": "newpassword1",
            },
        )
        self.assertEqual(response.status_code, 302)
        saved = json.loads(self.auth_path.read_text(encoding="utf-8"))
        self.assertTrue(wp._verify_password(saved, "newpassword1"))

    def test_scan_route_removed(self) -> None:
        self._write_auth()
        self._login()
        response = self.client.get("/scan")
        self.assertEqual(response.status_code, 404)
        response = self.client.post("/scan", data={"csrf_token": self._get_csrf("/")})
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()


class DamagedAuthFileTests(unittest.TestCase):
    """A password file that exists but cannot be used locks the panel."""

    DAMAGED = {
        "truncated JSON": b'{\n  "secret_key": "cccccccccccccccc",\n  "password_hash": ',
        "empty file": b"",
        "not an object": b'["scrypt:32768:8:1$salt$abc"]',
        "hash not a string": b'{"secret_key": "cccccccccccccccc", "password_hash": 42}',
        "not UTF-8": b'{"password_hash": "\xff"}',
        "old salt/hash format": b'{"salt": "00ff", "hash": "abcd"}',
    }

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self._tmpdir.name) / wp.AUTH_FILE
        self._patches = [
            mock.patch.object(wp, "_auth_path", return_value=self.auth_path),
            mock.patch.object(wp, "_auth_save_path", return_value=self.auth_path),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in self._patches:
            patch.stop()
        self._tmpdir.cleanup()

    def _client(self):
        app = wp.create_app()
        app.config["TESTING"] = True
        return app.test_client()

    def _assert_locked(self, client) -> None:
        for path in ("/", "/login", "/set-password", "/control/KID-PC", "/no-such-page"):
            with self.subTest(path=path), self.assertLogs(wp.logger, "ERROR"):
                response = client.get(path)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.mimetype, "text/plain")
                self.assertIn(str(self.auth_path), response.get_data(as_text=True))
                self.assertEqual(response.headers["Cache-Control"], wp.DYNAMIC_CACHE_CONTROL)
        self.assertEqual(client.get("/agent/v1/discover").status_code, 200)
        self.assertEqual(client.get("/static/css/panel.css").status_code, 200)

    def test_damaged_file_locks_the_panel_and_is_left_alone(self) -> None:
        for name, content in self.DAMAGED.items():
            with self.subTest(name):
                self.auth_path.write_bytes(content)
                self.assertIsNotNone(wp.auth_file_problem())
                self.assertIsNone(wp.load_auth_record())
                client = self._client()
                self._assert_locked(client)
                # No way to set a password over the damaged file: the locked
                # pages carry no CSRF token, so a POST fails that check first.
                response = client.post(
                    "/set-password",
                    data={"password": "attacker123", "password_confirm": "attacker123"},
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.auth_path.read_bytes(), content)
                with self.assertRaises(RuntimeError):
                    wp.save_password("attacker123")
                self.assertEqual(self.auth_path.read_bytes(), content)

    def test_directory_in_place_of_the_file_locks_the_panel(self) -> None:
        self.auth_path.mkdir()
        self.assertIsNotNone(wp.auth_file_problem())
        self._assert_locked(self._client())

    @unittest.skipIf(
        not hasattr(os, "geteuid") or os.geteuid() == 0, "needs POSIX permissions, not root"
    )
    def test_unreadable_file_locks_the_panel(self) -> None:
        self.auth_path.write_text('{"password_hash": "x"}', encoding="utf-8")
        self.auth_path.chmod(0)
        try:
            self.assertIn("cannot read", wp.auth_file_problem() or "")
            self._assert_locked(self._client())
        finally:
            self.auth_path.chmod(0o600)

    def test_a_logged_in_session_is_locked_too(self) -> None:
        self.auth_path.write_text(
            json.dumps(
                {
                    "secret_key": "c" * 32,
                    "password_hash": generate_password_hash("supersecret1", method="scrypt"),
                }
            ),
            encoding="utf-8",
        )
        client = self._client()
        with client.session_transaction() as sess:
            sess[wp.SESSION_AUTH_KEY] = True
        self.assertEqual(client.get("/").status_code, 200)
        good = self.auth_path.read_bytes()
        self.auth_path.write_bytes(good[:20])
        self._assert_locked(client)
        self.auth_path.write_bytes(good)
        self.assertEqual(client.get("/").status_code, 200)

    def test_missing_file_and_missing_hash_still_mean_no_password(self) -> None:
        self.assertEqual(wp.read_auth_file(), (None, None))
        self.assertEqual(self._client().get("/").status_code, 200)
        self.auth_path.write_text('{"secret_key": "cccccccccccccccc"}', encoding="utf-8")
        self.assertIsNone(wp.auth_file_problem())
        self.assertFalse(wp.password_is_configured())


class AuthPathTests(unittest.TestCase):
    def test_damaged_canonical_file_is_not_skipped_for_the_legacy_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config, package = Path(tmp) / "config", Path(tmp) / "package"
            config.mkdir()
            package.mkdir()
            (package / wp.AUTH_FILE).write_text('{"password_hash": "legacy"}', encoding="utf-8")
            with (
                mock.patch.object(wp, "config_dir", return_value=config),
                mock.patch.object(wp, "package_dir", return_value=package),
            ):
                self.assertEqual(wp._auth_path(), package / wp.AUTH_FILE)
                (config / wp.AUTH_FILE).mkdir()
                self.assertEqual(wp._auth_path(), config / wp.AUTH_FILE)
                self.assertIsNotNone(wp.auth_file_problem())

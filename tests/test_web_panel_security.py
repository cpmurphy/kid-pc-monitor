"""Tests for web panel security hardening (CSRF, redirects, password change)."""

from __future__ import annotations

import json
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
        self.assertIsNotNone(match, "csrf token not found in page")
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
        with mock.patch.object(wp, "perform_action", return_value=(True, "ok")):
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


if __name__ == "__main__":
    unittest.main()

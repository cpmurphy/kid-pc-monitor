"""Tests for web panel auth file handling."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from werkzeug.security import generate_password_hash

from kid_pc_monitor import web_panel as wp


class WebPanelAuthTests(unittest.TestCase):
    def test_stored_password_hash_requires_canonical_key(self) -> None:
        self.assertIsNotNone(
            wp._stored_password_hash({"password_hash": "scrypt:abc"})
        )
        self.assertIsNone(wp._stored_password_hash({"hash": "scrypt:abc"}))
        self.assertIsNone(wp._stored_password_hash({"password_hash": ""}))
        self.assertIsNone(wp._stored_password_hash({}))

    def test_panel_secret_key_requires_canonical_key(self) -> None:
        self.assertEqual(
            wp._panel_secret_key({"secret_key": "b" * 16}),
            "b" * 16,
        )
        self.assertIsNone(wp._panel_secret_key({"salt": "a" * 16}))
        self.assertIsNone(wp._panel_secret_key({"secret_key": "short"}))

    def test_auth_file_allows_login(self) -> None:
        password = "supersecret1"
        auth = {
            "secret_key": "c" * 32,
            "password_hash": generate_password_hash(password, method="scrypt"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / wp.AUTH_FILE
            auth_path.write_text(json.dumps(auth), encoding="utf-8")
            with mock.patch.object(wp, "_auth_path", return_value=auth_path):
                record = wp.load_auth_record()
                self.assertTrue(wp.password_is_configured())
                self.assertTrue(wp._verify_password(record, password))
                self.assertFalse(wp._verify_password(record, "wrong"))

    def test_save_password_writes_canonical_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            save_path = Path(tmp) / wp.AUTH_FILE
            with mock.patch.object(wp, "_auth_save_path", return_value=save_path):
                wp.save_password("supersecret1")
            saved = json.loads(save_path.read_text(encoding="utf-8"))
            self.assertIn("secret_key", saved)
            self.assertIn("password_hash", saved)
            self.assertNotIn("salt", saved)
            self.assertNotIn("hash", saved)
            self.assertTrue(wp._verify_password(saved, "supersecret1"))


if __name__ == "__main__":
    unittest.main()

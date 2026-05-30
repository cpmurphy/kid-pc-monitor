"""Tests for secrets_store encrypted-at-rest secret storage."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kid_pc_monitor import secrets_store


class SecretsStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp_path = Path(self._tmpdir.name) / "secrets"
        # Pin storage to an isolated directory so the machine-wide and per-user
        # search paths never touch the real filesystem during tests.
        self._prev_secrets_dir = os.environ.get(secrets_store._SECRETS_DIR_ENV)
        os.environ[secrets_store._SECRETS_DIR_ENV] = str(tmp_path)
        self._patch_kdf = mock.patch.object(secrets_store, "_derive_key")
        self._derive_key = self._patch_kdf.start()

        # Use a fresh Fernet key per test run so tokens are reproducible within
        # a test without depending on the actual KDF.
        from cryptography.fernet import Fernet
        self._fake_key = Fernet.generate_key()
        self._derive_key.return_value = self._fake_key

    def tearDown(self) -> None:
        self._patch_kdf.stop()
        if self._prev_secrets_dir is None:
            os.environ.pop(secrets_store._SECRETS_DIR_ENV, None)
        else:
            os.environ[secrets_store._SECRETS_DIR_ENV] = self._prev_secrets_dir
        self._tmpdir.cleanup()

    def _secrets_dir(self) -> Path:
        return secrets_store._secrets_dir()

    def _secret_path(self, name: str) -> Path:
        return secrets_store._secret_path(name)

    def test_save_and_load_round_trip(self) -> None:
        secrets_store.save_secret("api-key", "super-secret-value")
        self.assertEqual(secrets_store.load_secret("api-key"), "super-secret-value")

    def test_load_missing_returns_none(self) -> None:
        self.assertIsNone(secrets_store.load_secret("nonexistent"))

    def test_delete_removes_file(self) -> None:
        secrets_store.save_secret("temp", "value")
        self.assertTrue(self._secret_path("temp").is_file())
        self.assertTrue(secrets_store.delete_secret("temp"))
        self.assertFalse(self._secret_path("temp").exists())
        self.assertIsNone(secrets_store.load_secret("temp"))

    def test_delete_nonexistent_returns_false(self) -> None:
        self.assertFalse(secrets_store.delete_secret("never-saved"))

    def test_different_names_do_not_collide(self) -> None:
        secrets_store.save_secret("a", "alpha")
        secrets_store.save_secret("b", "beta")
        self.assertEqual(secrets_store.load_secret("a"), "alpha")
        self.assertEqual(secrets_store.load_secret("b"), "beta")

    def test_overwrite_updates_value(self) -> None:
        secrets_store.save_secret("key", "old")
        secrets_store.save_secret("key", "new")
        self.assertEqual(secrets_store.load_secret("key"), "new")

    def test_encrypted_at_rest(self) -> None:
        secrets_store.save_secret("key", "plaintext-secret")
        raw = self._secret_path("key").read_bytes()
        self.assertNotIn(b"plaintext-secret", raw)

    def test_generate_secret_default_length(self) -> None:
        s = secrets_store.generate_secret()
        self.assertEqual(len(s), 64)  # 32 bytes → 64 hex chars
        self.assertTrue(all(c in "0123456789abcdef" for c in s))

    def test_generate_secret_custom_length(self) -> None:
        s = secrets_store.generate_secret(16)
        self.assertEqual(len(s), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in s))

    def test_generate_secret_is_random(self) -> None:
        a = secrets_store.generate_secret()
        b = secrets_store.generate_secret()
        self.assertNotEqual(a, b)

    def test_different_key_cannot_decrypt(self) -> None:
        secrets_store.save_secret("key", "original")
        # Switch to a different key
        self._derive_key.return_value = self._fake_key[:-1] + b"X"
        self.assertIsNone(secrets_store.load_secret("key"))

    def test_corrupt_file_returns_none(self) -> None:
        secrets_store.save_secret("key", "value")
        self._secret_path("key").write_bytes(b"not-a-valid-fernet-token")
        self.assertIsNone(secrets_store.load_secret("key"))


class SecretsStoreSearchPathTests(unittest.TestCase):
    """Cross-account (mode 2) storage: machine-wide vs per-user directories."""

    def setUp(self) -> None:
        self._machine = tempfile.TemporaryDirectory()
        self._user = tempfile.TemporaryDirectory()
        # No explicit override: exercise the real machine/per-user search order.
        os.environ.pop(secrets_store._SECRETS_DIR_ENV, None)
        self._patch_machine = mock.patch.object(
            secrets_store, "_machine_secrets_dir", return_value=Path(self._machine.name)
        )
        self._patch_user = mock.patch.object(
            secrets_store, "_user_secrets_dir", return_value=Path(self._user.name)
        )
        self._patch_machine.start()
        self._patch_user.start()
        self._patch_kdf = mock.patch.object(secrets_store, "_derive_key")
        self._derive_key = self._patch_kdf.start()
        from cryptography.fernet import Fernet
        self._derive_key.return_value = Fernet.generate_key()

    def tearDown(self) -> None:
        self._patch_kdf.stop()
        self._patch_user.stop()
        self._patch_machine.stop()
        self._machine.cleanup()
        self._user.cleanup()

    def test_save_prefers_machine_wide_dir(self) -> None:
        secrets_store.save_secret("panel-agent-shared-secret", "hunter2")
        machine_file = Path(self._machine.name) / "panel-agent-shared-secret.enc"
        user_file = Path(self._user.name) / "panel-agent-shared-secret.enc"
        self.assertTrue(machine_file.is_file())
        self.assertFalse(user_file.is_file())

    def test_load_finds_machine_secret_when_user_dir_empty(self) -> None:
        # Simulates an admin installer writing the secret to the machine-wide
        # location while the child's per-user directory has nothing.
        secrets_store.save_secret("shared", "from-installer")
        self.assertEqual(secrets_store.load_secret("shared"), "from-installer")

    def test_falls_back_to_user_dir_when_machine_unwritable(self) -> None:
        with mock.patch.object(
            secrets_store, "_machine_secrets_dir", return_value=Path("/proc/cannot/write")
        ):
            secrets_store.save_secret("shared", "value")
        self.assertTrue((Path(self._user.name) / "shared.enc").is_file())
        self.assertEqual(secrets_store.load_secret("shared"), "value")


class SecretsStoreKeyDerivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._patch_config = mock.patch.object(
            secrets_store, "config_dir", return_value=Path("/nonexistent")
        )
        self._patch_config.start()

    def tearDown(self) -> None:
        # Undo any key derivation patches so the real _derive_key is restored.
        secrets_store._derive_key.__wrapped__ = None
        self._patch_config.stop()
        for suffix in ("", "_SECRET_KEY"):
            env_var = f"KID_PC_MONITOR{suffix}"
            try:
                del os.environ[env_var]
            except KeyError:
                pass

    def _call_real_derive(self) -> bytes:
        with mock.patch.object(secrets_store, "_derive_key", wraps=secrets_store._derive_key):
            from cryptography.fernet import Fernet
            for suffix in ("", "_SECRET_KEY"):
                env_var = f"KID_PC_MONITOR{suffix}"
                try:
                    del os.environ[env_var]
                except KeyError:
                    pass
            return secrets_store._derive_key()

    def test_derive_key_without_env_override(self) -> None:
        for suffix in ("", "_SECRET_KEY"):
            env_var = f"KID_PC_MONITOR{suffix}"
            try:
                del os.environ[env_var]
            except KeyError:
                pass
        key = secrets_store._derive_key()
        self.assertEqual(len(key), 44)  # 32 bytes base64url-encoded
        fernet = __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet
        fernet(key)  # must not raise

    def test_env_override_produces_different_key(self) -> None:
        for suffix in ("", "_SECRET_KEY"):
            env_var = f"KID_PC_MONITOR{suffix}"
            try:
                del os.environ[env_var]
            except KeyError:
                pass
        default_key = secrets_store._derive_key()
        os.environ["KID_PC_MONITOR_SECRET_KEY"] = "custom-bootstrap-material"
        custom_key = secrets_store._derive_key()
        self.assertNotEqual(default_key, custom_key)
        self.assertEqual(len(custom_key), 44)


if __name__ == "__main__":
    unittest.main()
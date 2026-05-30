"""Tests for the panel <-> agent shared-secret prompt."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet

from kid_pc_monitor import secrets_store, shared_secret


class _FakeGetpass:
    """Callable that returns queued responses in order, ignoring the prompt."""

    def __init__(self, responses):
        self._responses = list(responses)

    def __call__(self, prompt=""):
        return self._responses.pop(0)


class SharedSecretTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp_path = Path(self._tmpdir.name) / "secrets"
        # Pin storage to an isolated directory so neither the machine-wide nor
        # the per-user search path touches the real filesystem.
        self._prev_secrets_dir = os.environ.get(secrets_store._SECRETS_DIR_ENV)
        os.environ[secrets_store._SECRETS_DIR_ENV] = str(tmp_path)
        self._patch_kdf = mock.patch.object(
            secrets_store, "_derive_key", return_value=Fernet.generate_key()
        )
        self._patch_kdf.start()

    def tearDown(self) -> None:
        self._patch_kdf.stop()
        if self._prev_secrets_dir is None:
            os.environ.pop(secrets_store._SECRETS_DIR_ENV, None)
        else:
            os.environ[secrets_store._SECRETS_DIR_ENV] = self._prev_secrets_dir
        self._tmpdir.cleanup()

    def test_prompt_for_shared_secret_matching(self) -> None:
        getpass_fn = _FakeGetpass(["correct horse battery", "correct horse battery"])
        result = shared_secret.prompt_for_shared_secret(getpass_fn=getpass_fn)
        self.assertEqual(result, "correct horse battery")

    def test_prompt_strips_whitespace(self) -> None:
        getpass_fn = _FakeGetpass(["  padded secret  ", "padded secret"])
        result = shared_secret.prompt_for_shared_secret(getpass_fn=getpass_fn)
        self.assertEqual(result, "padded secret")

    def test_prompt_rejects_too_short_then_accepts(self) -> None:
        getpass_fn = _FakeGetpass(["short", "long enough secret", "long enough secret"])
        result = shared_secret.prompt_for_shared_secret(getpass_fn=getpass_fn)
        self.assertEqual(result, "long enough secret")

    def test_prompt_retries_on_mismatch(self) -> None:
        getpass_fn = _FakeGetpass(
            ["first attempt here", "mismatch attempt", "second attempt here", "second attempt here"]
        )
        result = shared_secret.prompt_for_shared_secret(getpass_fn=getpass_fn)
        self.assertEqual(result, "second attempt here")

    def test_prompt_cancel_returns_none(self) -> None:
        def cancel(prompt=""):
            raise KeyboardInterrupt

        self.assertIsNone(shared_secret.prompt_for_shared_secret(getpass_fn=cancel))

    def test_prompt_and_store_persists_secret(self) -> None:
        getpass_fn = _FakeGetpass(["my shared phrase", "my shared phrase"])
        result = shared_secret.prompt_and_store_shared_secret(getpass_fn=getpass_fn)
        self.assertEqual(result, "my shared phrase")
        self.assertEqual(
            secrets_store.load_secret(shared_secret.SHARED_SECRET_NAME),
            "my shared phrase",
        )

    def test_prompt_and_store_keep_existing(self) -> None:
        secrets_store.save_secret(shared_secret.SHARED_SECRET_NAME, "already set")

        def fail_getpass(prompt=""):
            raise AssertionError("should not prompt when keeping existing secret")

        result = shared_secret.prompt_and_store_shared_secret(
            getpass_fn=fail_getpass,
            input_fn=lambda prompt="": "y",
        )
        self.assertEqual(result, "already set")
        self.assertEqual(
            secrets_store.load_secret(shared_secret.SHARED_SECRET_NAME),
            "already set",
        )

    def test_keep_existing_migrates_to_preferred_location(self) -> None:
        # Simulate a secret left behind by an older version in the per-user
        # directory, with the machine-wide directory empty (the mode 2 bug).
        machine = Path(self._tmpdir.name) / "machine"
        user = Path(self._tmpdir.name) / "user"
        name = shared_secret.SHARED_SECRET_NAME
        os.environ.pop(secrets_store._SECRETS_DIR_ENV, None)  # exercise real search order
        with mock.patch.object(
            secrets_store, "_machine_secrets_dir", return_value=machine
        ), mock.patch.object(
            secrets_store, "_user_secrets_dir", return_value=user
        ):
            user.mkdir(parents=True, exist_ok=True)
            token = Fernet(secrets_store._derive_key()).encrypt(b"legacy")
            (user / f"{name}.enc").write_bytes(token)

            result = shared_secret.prompt_and_store_shared_secret(
                getpass_fn=_FakeGetpass([]),
                input_fn=lambda prompt="": "y",
            )

            self.assertEqual(result, "legacy")
            self.assertTrue((machine / f"{name}.enc").is_file())
            self.assertFalse((user / f"{name}.enc").is_file())

    def test_prompt_and_store_replace_existing(self) -> None:
        secrets_store.save_secret(shared_secret.SHARED_SECRET_NAME, "old secret value")
        getpass_fn = _FakeGetpass(["brand new secret", "brand new secret"])
        result = shared_secret.prompt_and_store_shared_secret(
            getpass_fn=getpass_fn,
            input_fn=lambda prompt="": "n",
        )
        self.assertEqual(result, "brand new secret")
        self.assertEqual(
            secrets_store.load_secret(shared_secret.SHARED_SECRET_NAME),
            "brand new secret",
        )


if __name__ == "__main__":
    unittest.main()

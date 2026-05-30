"""Tests for the panel <-> agent shared-secret prompt."""

from __future__ import annotations

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
        tmp_path = Path(self._tmpdir.name)
        self._patch_config = mock.patch.object(
            secrets_store, "config_dir", return_value=tmp_path
        )
        self._patch_config.start()
        self._patch_kdf = mock.patch.object(
            secrets_store, "_derive_key", return_value=Fernet.generate_key()
        )
        self._patch_kdf.start()

    def tearDown(self) -> None:
        self._patch_kdf.stop()
        self._patch_config.stop()
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

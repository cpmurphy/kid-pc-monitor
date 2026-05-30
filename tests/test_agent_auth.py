"""Tests for the HMAC authentication primitives (agent_auth.py)."""

from __future__ import annotations

import hashlib
import hmac
import unittest

from kid_pc_monitor import agent_auth


class KeyDerivationTests(unittest.TestCase):
    def test_unnamed_key_is_raw_secret(self) -> None:
        self.assertEqual(agent_auth.derive_key("hunter2", None), b"hunter2")

    def test_named_key_mixes_in_hostname(self) -> None:
        key = agent_auth.derive_key("hunter2", "bedroom-pc")
        expected = hmac.new(b"hunter2", b"bedroom-pc", hashlib.sha256).digest()
        self.assertEqual(key, expected)

    def test_different_hosts_get_different_keys(self) -> None:
        bedroom = agent_auth.derive_key("hunter2", "bedroom-pc")
        living = agent_auth.derive_key("hunter2", "living-room-pc")
        self.assertNotEqual(bedroom, living)


class SignatureTests(unittest.TestCase):
    def test_sign_and_verify_round_trip(self) -> None:
        key = agent_auth.derive_key("secret", "kid-pc")
        sig = agent_auth.compute_signature(key, "v 2\naction unlock")
        self.assertTrue(agent_auth.verify_signature(key, "v 2\naction unlock", sig))

    def test_verify_fails_on_tamper(self) -> None:
        key = agent_auth.derive_key("secret", "kid-pc")
        sig = agent_auth.compute_signature(key, "v 2\naction unlock")
        self.assertFalse(agent_auth.verify_signature(key, "v 2\naction lock", sig))

    def test_verify_fails_with_wrong_key(self) -> None:
        sig = agent_auth.compute_signature(agent_auth.derive_key("a", None), "msg")
        self.assertFalse(
            agent_auth.verify_signature(agent_auth.derive_key("b", None), "msg", sig)
        )

    def test_signature_is_base64url(self) -> None:
        sig = agent_auth.compute_signature(b"k", "payload")
        # base64url alphabet only (plus padding); never '+' or '/'.
        self.assertNotIn("+", sig)
        self.assertNotIn("/", sig)


class NonceTests(unittest.TestCase):
    def test_make_nonce_is_valid_and_unique(self) -> None:
        a, b = agent_auth.make_nonce(), agent_auth.make_nonce()
        self.assertNotEqual(a, b)
        self.assertTrue(agent_auth.is_valid_nonce(a))
        self.assertGreaterEqual(len(a), agent_auth.NONCE_MIN_HEX_CHARS)

    def test_short_or_nonhex_nonce_rejected(self) -> None:
        self.assertFalse(agent_auth.is_valid_nonce("abc"))
        self.assertFalse(agent_auth.is_valid_nonce("z" * 32))
        self.assertFalse(agent_auth.is_valid_nonce(12345))


class TimestampWindowTests(unittest.TestCase):
    def test_within_window(self) -> None:
        self.assertTrue(agent_auth.timestamp_in_window(1000, now=1000))
        self.assertTrue(
            agent_auth.timestamp_in_window(
                1000, now=1000 + agent_auth.TIMESTAMP_WINDOW_SECONDS
            )
        )

    def test_outside_window(self) -> None:
        self.assertFalse(
            agent_auth.timestamp_in_window(
                1000, now=1000 + agent_auth.TIMESTAMP_WINDOW_SECONDS + 1
            )
        )
        self.assertFalse(
            agent_auth.timestamp_in_window(
                1000, now=1000 - agent_auth.TIMESTAMP_WINDOW_SECONDS - 1
            )
        )


if __name__ == "__main__":
    unittest.main()

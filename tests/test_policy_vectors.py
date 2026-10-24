"""The golden lock-policy vectors must match the Python implementation.

``testdata/policy/vectors.json`` is consumed by ``go/policy``.  After an
intentional change to ``lock_policy.py``, regenerate it with
``python tests/policy_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from policy_vectors_gen import VECTORS_PATH, build_vectors, render


class PolicyVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/policy_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "policy vectors.json is stale; run tests/policy_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

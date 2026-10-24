"""The golden request-dispatcher vectors must match the Python implementation.

``testdata/dispatcher/vectors.json`` is consumed by ``go/dispatcher``.  After an
intentional change to ``request_dispatcher.py``, regenerate it with
``python tests/dispatcher_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from dispatcher_vectors_gen import VECTORS_PATH, build_vectors, render


class DispatcherVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/dispatcher_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "dispatcher vectors.json is stale; run tests/dispatcher_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

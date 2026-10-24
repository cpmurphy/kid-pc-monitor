"""The golden protocol vectors must match the Python implementation.

``testdata/protocol/vectors.json`` is consumed by the Go package in ``go/``.
If this test fails after an intentional protocol change, regenerate the file
with ``python tests/protocol_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import json
import unittest

from protocol_vectors_gen import VECTORS_PATH, build_vectors, render


class ProtocolVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/protocol_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "vectors.json is stale; run tests/protocol_vectors_gen.py",
        )

    def test_vectors_cover_every_section(self) -> None:
        vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
        for section, cases in vectors.items():
            if isinstance(cases, list):
                self.assertTrue(cases, f"section {section} is empty")


if __name__ == "__main__":
    unittest.main()

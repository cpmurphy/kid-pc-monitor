"""The golden web-panel auth vectors must match the Python implementation.

``testdata/panelauth/vectors.json`` is consumed by ``go/panel/auth``.  After
an intentional change to the auth helpers in ``web_panel.py`` (or a werkzeug
upgrade that changes its hashes), regenerate it with
``python tests/panelauth_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from panelauth_vectors_gen import VECTORS_PATH, build_vectors, render


class PanelAuthVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/panelauth_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "panelauth vectors.json is stale; run tests/panelauth_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

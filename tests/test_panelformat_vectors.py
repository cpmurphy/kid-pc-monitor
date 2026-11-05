"""The golden web-panel formatting vectors must match the Python implementation.

``testdata/panelformat/vectors.json`` is consumed by ``go/panel/format``.  After
an intentional change to ``panel_format.py`` or the helpers it covers in
``remote_client.py`` / ``scan_store.py``, regenerate it with
``python tests/panelformat_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from panelformat_vectors_gen import VECTORS_PATH, build_vectors, render


class PanelFormatVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/panelformat_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "panelformat vectors.json is stale; run tests/panelformat_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

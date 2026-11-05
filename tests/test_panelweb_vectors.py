"""The golden web-panel HTTP vectors must match the Python implementation.

``testdata/panelweb/vectors.json`` is consumed by ``go/panel/web``.  After
an intentional change to ``web_panel.py``, its templates or static files,
regenerate it (and the Go panel's static copy) with
``python tests/panelweb_vectors_gen.py`` and update the Go package and its
templates until ``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from panelweb_vectors_gen import VECTORS_PATH, build_vectors, render, static_copy_is_current


class PanelWebVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/panelweb_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "panelweb vectors.json is stale; run tests/panelweb_vectors_gen.py",
        )

    def test_go_static_copy_is_current(self) -> None:
        self.assertTrue(
            static_copy_is_current(),
            "go/panel/web/static differs from src/kid_pc_monitor/static; "
            "run tests/panelweb_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

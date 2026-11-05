"""The golden web-panel store vectors must match the Python implementation.

``testdata/panelstore/vectors.json`` is consumed by ``go/panel/store``.  After
an intentional change to ``panel_db.py``, ``scan_store.py``,
``snapshot_store.py`` or ``agent_sync_store.py``, regenerate it with
``python tests/panelstore_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from panelstore_vectors_gen import VECTORS_PATH, build_vectors, render


class PanelStoreVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/panelstore_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "panelstore vectors.json is stale; run tests/panelstore_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

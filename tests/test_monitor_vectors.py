"""The golden monitoring-loop vectors must match the Python implementation.

``testdata/monitor/vectors.json`` is consumed by ``go/monitor``.  After an
intentional change to ``pc_time_control.py``, regenerate it with
``python tests/monitor_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from monitor_vectors_gen import VECTORS_PATH, build_vectors, render


class MonitorVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/monitor_vectors_gen.py")
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            render(build_vectors()),
            "monitor vectors.json is stale; run tests/monitor_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

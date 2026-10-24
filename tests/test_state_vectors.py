"""The golden agent-state vectors must match the Python implementation.

``testdata/state/vectors.json`` is consumed by ``go/state``.  After an
intentional change to ``agent_state.py``, regenerate it with
``python tests/state_vectors_gen.py`` and update the Go package until
``go test ./...`` passes again.
"""

from __future__ import annotations

import unittest

from state_vectors_gen import VECTORS_PATH, build_vectors, render


class StateVectorsTests(unittest.TestCase):
    def test_vectors_file_is_current(self) -> None:
        self.assertTrue(VECTORS_PATH.exists(), "run tests/state_vectors_gen.py")
        with self.assertLogs("kid_pc_monitor.agent_state", level="WARNING"):
            # Building the vectors exercises the corrupt-file paths, which log warnings.
            current = render(build_vectors())
        self.assertEqual(
            VECTORS_PATH.read_text(encoding="utf-8"),
            current,
            "state vectors.json is stale; run tests/state_vectors_gen.py",
        )


if __name__ == "__main__":
    unittest.main()

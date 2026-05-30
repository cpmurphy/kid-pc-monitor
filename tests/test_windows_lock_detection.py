"""Tests for the pure WTS SessionFlags interpretation used by the Windows agent.

The live ctypes WTS query only runs on Windows, but the flag-to-lock-state
logic (including the Windows 7 / Server 2008 R2 inversion) is platform neutral
and can be exercised anywhere. The Windows platform module imports cleanly off
Windows because its only Windows-only dependency (tkinter) is imported lazily.
"""

from __future__ import annotations

import unittest

from kid_pc_monitor.platforms.windows import (
    _WTS_SESSIONSTATE_LOCK,
    _WTS_SESSIONSTATE_UNKNOWN,
    _WTS_SESSIONSTATE_UNLOCK,
    _session_flags_indicate_locked,
)


class SessionFlagsInterpretationTests(unittest.TestCase):
    def test_lock_flag_means_locked(self) -> None:
        self.assertTrue(
            _session_flags_indicate_locked(_WTS_SESSIONSTATE_LOCK, inverted=False)
        )

    def test_unlock_flag_means_unlocked(self) -> None:
        self.assertFalse(
            _session_flags_indicate_locked(_WTS_SESSIONSTATE_UNLOCK, inverted=False)
        )

    def test_unknown_flag_returns_none(self) -> None:
        self.assertIsNone(
            _session_flags_indicate_locked(_WTS_SESSIONSTATE_UNKNOWN, inverted=False)
        )

    def test_inversion_reverses_lock_and_unlock(self) -> None:
        # Win7 / Server 2008 R2 defect: LOCK flag actually means unlocked.
        self.assertFalse(
            _session_flags_indicate_locked(_WTS_SESSIONSTATE_LOCK, inverted=True)
        )
        self.assertTrue(
            _session_flags_indicate_locked(_WTS_SESSIONSTATE_UNLOCK, inverted=True)
        )

    def test_unexpected_flag_value_returns_none(self) -> None:
        self.assertIsNone(_session_flags_indicate_locked(42, inverted=False))


if __name__ == "__main__":
    unittest.main()

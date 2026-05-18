import unittest
from datetime import datetime, time as dtime

from src.lock_policy import lock_decision, minutes_until_lock, should_monitor_user


class LockPolicyTests(unittest.TestCase):
    def test_default_monitors_all_users(self):
        self.assertTrue(should_monitor_user("kid"))

    def test_monitored_users_allow_only_listed_users(self):
        self.assertTrue(should_monitor_user("kid", monitored_users=["kid"]))
        self.assertFalse(should_monitor_user("parent", monitored_users=["kid"]))

    def test_exempt_users_skip_parent_accounts(self):
        self.assertFalse(should_monitor_user("parent", exempt_users=["parent"]))
        self.assertTrue(should_monitor_user("kid", exempt_users=["parent"]))

    def test_scheduled_lock_applies_after_bedtime_when_kid_signs_back_in(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 21, 5),
            lock_times=[dtime(21, 0)],
            usage_limit=None,
            start_time=datetime(2026, 5, 17, 18, 0),
        )

        self.assertTrue(decision.should_lock)
        self.assertEqual(decision.reason, "Past scheduled lock time 21:00")

    def test_manual_lock_keeps_relocking_after_kid_signs_back_in(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 15, 45),
            lock_times=[],
            usage_limit=None,
            start_time=datetime(2026, 5, 17, 15, 0),
            manual_lock_active=True,
        )

        self.assertTrue(decision.should_lock)
        self.assertEqual(decision.reason, "Manual lock requested")

    def test_scheduled_lock_does_not_carry_past_midnight(self):
        decision = lock_decision(
            now=datetime(2026, 5, 18, 0, 5),
            lock_times=[dtime(21, 0)],
            usage_limit=None,
            start_time=datetime(2026, 5, 18, 0, 0),
        )

        self.assertFalse(decision.should_lock)

    def test_usage_limit_still_applies_after_agent_restarts_same_day(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 10, 45),
            lock_times=[],
            usage_limit=30,
            start_time=datetime(2026, 5, 17, 10, 0),
        )

        self.assertTrue(decision.should_lock)
        self.assertEqual(decision.reason, "Usage limit of 30 minutes reached")

    def test_unmonitored_user_is_never_locked(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 21, 5),
            lock_times=[dtime(21, 0)],
            usage_limit=30,
            start_time=datetime(2026, 5, 17, 10, 0),
            monitor_user=False,
            manual_lock_active=True,
        )

        self.assertFalse(decision.should_lock)

    def test_minutes_until_lock_returns_zero_inside_active_lock_window(self):
        remaining = minutes_until_lock(
            now=datetime(2026, 5, 17, 21, 5),
            lock_times=[dtime(21, 0)],
            usage_limit=None,
            start_time=datetime(2026, 5, 17, 18, 0),
        )

        self.assertEqual(remaining, 0)

    def test_minutes_until_lock_handles_month_end(self):
        remaining = minutes_until_lock(
            now=datetime(2026, 1, 31, 20, 0),
            lock_times=[dtime(21, 0)],
            usage_limit=None,
            start_time=datetime(2026, 1, 31, 18, 0),
        )

        self.assertEqual(remaining, 60)


if __name__ == "__main__":
    unittest.main()

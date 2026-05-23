import unittest
from datetime import datetime, timedelta, time as dtime

from kid_pc_monitor.lock_policy import (
    is_in_bedtime_curfew,
    lock_decision,
    minutes_until_lock,
    should_monitor_user,
    usage_period_date,
)


class LockPolicyTests(unittest.TestCase):
    def test_default_monitors_all_users(self):
        self.assertTrue(should_monitor_user("kid"))

    def test_monitored_users_allow_only_listed_users(self):
        self.assertTrue(should_monitor_user("kid", monitored_users=["kid"]))
        self.assertFalse(should_monitor_user("parent", monitored_users=["kid"]))

    def test_exempt_users_skip_parent_accounts(self):
        self.assertFalse(should_monitor_user("parent", exempt_users=["parent"]))
        self.assertTrue(should_monitor_user("kid", exempt_users=["parent"]))

    def test_bedtime_lock_applies_after_bedtime_when_kid_signs_back_in(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 21, 5),
            bed_time=dtime(21, 0),
            effective_usage_limit_minutes=None,
            accumulated_minutes=0,
        )

        self.assertTrue(decision.should_lock)
        self.assertEqual(decision.reason, "Past bedtime 21:00")

    def test_manual_lock_keeps_relocking_after_kid_signs_back_in(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 15, 45),
            bed_time=None,
            effective_usage_limit_minutes=None,
            accumulated_minutes=0,
            manual_lock_active=True,
        )

        self.assertTrue(decision.should_lock)
        self.assertEqual(decision.reason, "Manual lock requested")

    def test_bedtime_stays_active_until_wake_time(self):
        decision = lock_decision(
            now=datetime(2026, 5, 18, 0, 5),
            bed_time=dtime(21, 0),
            effective_usage_limit_minutes=None,
            accumulated_minutes=0,
            wake_time=dtime(7, 0),
        )

        self.assertTrue(decision.should_lock)
        self.assertIn("wake-up", decision.reason.lower())

    def test_bedtime_releases_after_wake_time(self):
        decision = lock_decision(
            now=datetime(2026, 5, 18, 8, 0),
            bed_time=dtime(21, 0),
            effective_usage_limit_minutes=None,
            accumulated_minutes=0,
            wake_time=dtime(7, 0),
        )

        self.assertFalse(decision.should_lock)

    def test_usage_period_date_rolls_at_wake_not_midnight(self):
        before_wake = datetime(2026, 5, 18, 6, 30)
        after_wake = datetime(2026, 5, 18, 7, 30)
        self.assertEqual(
            usage_period_date(before_wake, dtime(7, 0)),
            before_wake.date() - timedelta(days=1),
        )
        self.assertEqual(usage_period_date(after_wake, dtime(7, 0)), after_wake.date())

    def test_is_in_bedtime_curfew_overnight_window(self):
        self.assertTrue(
            is_in_bedtime_curfew(datetime(2026, 5, 17, 22, 0), dtime(21, 0), dtime(7, 0))
        )
        self.assertTrue(
            is_in_bedtime_curfew(datetime(2026, 5, 18, 6, 0), dtime(21, 0), dtime(7, 0))
        )
        self.assertFalse(
            is_in_bedtime_curfew(datetime(2026, 5, 18, 10, 0), dtime(21, 0), dtime(7, 0))
        )

    def test_usage_limit_locks_once_accumulated_reaches_limit(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 10, 45),
            bed_time=None,
            effective_usage_limit_minutes=30,
            accumulated_minutes=30,
        )

        self.assertTrue(decision.should_lock)
        self.assertIn("30", decision.reason)

    def test_usage_limit_includes_extension_in_effective_cap(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 10, 45),
            bed_time=None,
            effective_usage_limit_minutes=150,
            accumulated_minutes=150,
        )

        self.assertTrue(decision.should_lock)

    def test_usage_limit_does_not_lock_below_limit(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 18, 0),
            bed_time=None,
            effective_usage_limit_minutes=30,
            accumulated_minutes=12,
        )

        self.assertFalse(decision.should_lock)

    def test_unmonitored_user_is_never_locked(self):
        decision = lock_decision(
            now=datetime(2026, 5, 17, 21, 5),
            bed_time=dtime(21, 0),
            effective_usage_limit_minutes=30,
            accumulated_minutes=99,
            monitor_user=False,
            manual_lock_active=True,
        )

        self.assertFalse(decision.should_lock)

    def test_minutes_until_lock_returns_zero_inside_active_lock_window(self):
        remaining = minutes_until_lock(
            now=datetime(2026, 5, 17, 21, 5),
            bed_time=dtime(21, 0),
            effective_usage_limit_minutes=None,
            accumulated_minutes=0,
        )

        self.assertEqual(remaining, 0)

    def test_minutes_until_lock_handles_month_end(self):
        remaining = minutes_until_lock(
            now=datetime(2026, 1, 31, 20, 0),
            bed_time=dtime(21, 0),
            effective_usage_limit_minutes=None,
            accumulated_minutes=0,
        )

        self.assertEqual(remaining, 60)

    def test_minutes_until_lock_uses_remaining_budget_when_lower(self):
        remaining = minutes_until_lock(
            now=datetime(2026, 5, 17, 20, 0),
            bed_time=dtime(21, 0),
            effective_usage_limit_minutes=30,
            accumulated_minutes=25,
        )

        self.assertEqual(remaining, 5)


if __name__ == "__main__":
    unittest.main()

"""Tests for the externalized panel JS/CSS static modules and template wiring.

Behavioral testing of the JavaScript itself would require a JS toolchain this
project does not have; these tests assert that the modules are served and that
templates load the right scripts (data-* attributes, no inline handlers/scripts)
and stylesheets (base plus page-specific CSS only).
"""

from __future__ import annotations

import re
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db, scan_store
from kid_pc_monitor import web_panel as wp


def _sample_pc_info(**overrides: object) -> dict:
    base: dict = {
        "ip": "192.168.1.10",
        "hostname": "KidPC",
        "status": "UNLOCKED",
        "locked": False,
        "current_user": "child",
        "daily_limit": 120,
        "usage_limit": 120,
        "bed_time": "21:00",
        "wake_time": "07:00",
        "manual_lock_active": False,
        "enforcement_active": False,
        "enforcement_reason": None,
        "access_status": "Unlocked",
        "cumulative_extension_seconds": 0,
        "accumulated_seconds": 1800,
        "effective_limit_minutes": 120.0,
        "time_remaining": "90 minutes",
        "reachable": True,
    }
    base.update(overrides)
    return base


def _settings_for_reverse(**overrides: object) -> dict:
    """Agent settings payload stored on a ReverseSession.pc_info."""
    base: dict = {
        "name": "KidPC",
        "status": "UNLOCKED",
        "current_user": "child",
        "daily_limit": 120,
        "bed_time": "21:00",
        "wake_time": "07:00",
        "manual_lock": False,
        "cumulative_extension": 0,
        "accumulated_seconds": 1800,
        "time_remaining": 90,
        "enforcement_active": False,
        "enforcement_reason": None,
        "access_status": "Unlocked",
    }
    base.update(overrides)
    return base


# Inline event-handler attributes that must no longer appear in rendered pages.
_INLINE_HANDLER_RE = re.compile(r"on(click|change|submit|load|keydown)\s*=", re.I)


class WebPanelStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self._tmpdir.name) / wp.AUTH_FILE
        self.db_path = Path(self._tmpdir.name) / panel_db.DB_FILENAME
        self._patches = [
            mock.patch.object(wp, "_auth_path", return_value=self.auth_path),
            mock.patch.object(wp, "_auth_save_path", return_value=self.auth_path),
            mock.patch.object(panel_db, "_db_path_override", self.db_path),
        ]
        for patch in self._patches:
            patch.start()
        self.app = wp.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        for patch in self._patches:
            patch.stop()
        self._tmpdir.cleanup()

    def _seed_pc(self, **overrides: object) -> None:
        info = _sample_pc_info(**overrides)
        scan_store.record_poll_inspect(str(info["ip"]), info)

    def _live_reverse(self, ip: str = "192.168.1.10", **settings_overrides: object):
        session = mock.Mock()
        session.hostname = str(settings_overrides.get("name", "KidPC"))
        session.pc_info = _settings_for_reverse(**settings_overrides)
        reverse = mock.Mock()
        reverse.session_for_ip.return_value = session
        reverse.session_for_hostname.return_value = session
        return mock.patch.object(wp, "get_reverse_server", return_value=reverse)

    def _control_html(self) -> str:
        self._seed_pc()
        with self._live_reverse():
            response = self.client.get("/control/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def _daily_html(self) -> str:
        self._seed_pc()
        with self._live_reverse():
            response = self.client.get("/daily_settings/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def _index_html(self) -> str:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def _set_password_html(self) -> str:
        response = self.client.get("/set-password")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def _login_html_with_password(self) -> str:
        with mock.patch.object(wp, "password_is_configured", return_value=True):
            response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def _logs_html(self) -> str:
        self._seed_pc()
        response = self.client.get("/logs/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def _usage_html(self) -> str:
        response = self.client.get("/usage/child")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_css_modules_served(self) -> None:
        cases = [
            ("/static/css/panel.css", "font-family"),
            ("/static/css/home.css", "pc-card"),
            ("/static/css/action-pages.css", "action-group"),
            ("/static/css/control.css", "quick-limit"),
            ("/static/css/daily-settings.css", 'input[type="time"]'),
            ("/static/css/logs.css", "agent-log-view"),
            ("/static/css/usage.css", "usage-table"),
            ("/static/css/auth.css", "page-login"),
        ]
        for path, needle in cases:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                body = response.get_data(as_text=True)
                self.assertIn(needle, body)

    def test_legacy_panel_css_removed(self) -> None:
        response = self.client.get("/static/panel.css")
        self.assertEqual(response.status_code, 404)

    def test_index_loads_home_css_only(self) -> None:
        html = self._index_html()
        self.assertIn("css/panel.css", html)
        self.assertIn("css/home.css", html)
        self.assertNotIn("css/action-pages.css", html)
        self.assertNotIn("css/control.css", html)

    def test_control_loads_action_and_control_css(self) -> None:
        html = self._control_html()
        self.assertIn("css/panel.css", html)
        self.assertIn("css/action-pages.css", html)
        self.assertIn("css/control.css", html)
        self.assertNotIn("css/home.css", html)

    def test_daily_settings_loads_action_and_daily_css(self) -> None:
        html = self._daily_html()
        self.assertIn("css/action-pages.css", html)
        self.assertIn("css/daily-settings.css", html)
        self.assertNotIn("css/control.css", html)

    def test_auth_pages_load_auth_css_only(self) -> None:
        for html in (self._set_password_html(), self._login_html_with_password()):
            with self.subTest(page=html[:60]):
                self.assertIn("css/panel.css", html)
                self.assertIn("css/auth.css", html)
                self.assertNotIn("css/home.css", html)
                self.assertNotIn("css/action-pages.css", html)

    def test_logs_loads_action_and_logs_css(self) -> None:
        html = self._logs_html()
        self.assertIn("css/action-pages.css", html)
        self.assertIn("css/logs.css", html)
        self.assertNotIn("css/control.css", html)
        self.assertIn("not connected", html.lower())

    def test_usage_loads_action_and_usage_css(self) -> None:
        html = self._usage_html()
        self.assertIn("css/action-pages.css", html)
        self.assertIn("css/usage.css", html)
        self.assertNotIn("css/home.css", html)

    def test_js_modules_served(self) -> None:
        cases = [
            ("/static/js/core.js", "postAction"),
            ("/static/js/core.js", "refreshPageStats"),
            ("/static/js/core.js", "startControlPagePoll"),
            ("/static/js/home.js", "page-home"),
            ("/static/js/control.js", "registerHandlers"),
            ("/static/js/daily-settings.js", "save-daily-limit"),
            ("/static/js/logs.js", "agent-log"),
        ]
        for path, needle in cases:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                body = response.get_data(as_text=True)
                self.assertIn(needle, body)

    def test_panel_js_removed(self) -> None:
        response = self.client.get("/static/panel.js")
        self.assertEqual(response.status_code, 404)

    def test_index_loads_home_js(self) -> None:
        html = self._index_html()
        self.assertIn("js/home.js", html)
        self.assertNotIn("panel.js", html)

    def test_control_loads_control_js(self) -> None:
        html = self._control_html()
        self.assertIn("js/control.js", html)
        self.assertNotIn("panel.js", html)

    def test_control_has_today_stats_container(self) -> None:
        html = self._control_html()
        self.assertIn('id="today-stats"', html)

    def test_control_stats_endpoint_returns_today_section(self) -> None:
        self._seed_pc()
        with self._live_reverse():
            response = self.client.get("/control/192.168.1.10/stats")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Today", html)
        self.assertIn("Unlocked", html)
        self.assertIn("Daily allowance", html)
        self.assertNotIn('id="today-stats"', html)

    def test_control_stats_poll_source_uses_cached_registry(self) -> None:
        cached = _sample_pc_info(access_status="Locked", locked=True)
        with mock.patch.object(wp, "get_scan_pc", return_value=cached):
            with mock.patch.object(wp, "get_reverse_server") as reverse_mock:
                response = self.client.get("/control/192.168.1.10/stats?source=poll")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Locked", html)
        reverse_mock.assert_not_called()

    def test_control_poll_meta_returns_updated_at(self) -> None:
        updated = datetime.now().astimezone().replace(microsecond=0)
        with mock.patch.object(
            wp,
            "get_pc_poll_updated_at",
            return_value=updated,
        ):
            response = self.client.get("/control/192.168.1.10/poll-meta")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        assert payload is not None
        self.assertEqual(payload["updated_at"], updated.isoformat(timespec="seconds"))
        self.assertEqual(payload["poll_interval_sec"], 60)

    def test_passive_page_loads_no_panel_js(self) -> None:
        html = self._set_password_html()
        self.assertNotIn("js/", html)
        self.assertNotIn("panel.js", html)

    def test_control_uses_data_attributes(self) -> None:
        html = self._control_html()
        self.assertIn('data-ip="192.168.1.10"', html)
        self.assertIn('data-action="lock"', html)
        self.assertIn('data-action="grant-extension"', html)
        self.assertIn('data-action="quick-extend"', html)
        self.assertNotRegex(html, _INLINE_HANDLER_RE)
        self.assertNotIn("function performAction", html)

    def test_daily_settings_uses_data_attributes(self) -> None:
        html = self._daily_html()
        self.assertIn('data-ip="192.168.1.10"', html)
        self.assertIn('data-action="save-daily-limit"', html)
        self.assertIn('data-action="save-bed-time"', html)
        self.assertNotRegex(html, _INLINE_HANDLER_RE)
        self.assertNotIn("function postAction", html)

    def test_index_cards_navigate_via_data_attributes(self) -> None:
        self._seed_pc()
        html = self._index_html()
        self.assertIn('data-action="navigate"', html)
        self.assertIn('data-href="/control/KidPC"', html)
        self.assertNotRegex(html, _INLINE_HANDLER_RE)
        self.assertNotIn("setTimeout(", html)


if __name__ == "__main__":
    unittest.main()

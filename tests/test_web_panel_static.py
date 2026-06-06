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
from pathlib import Path
from unittest import mock

from kid_pc_monitor import panel_db
from kid_pc_monitor import web_panel as wp
from kid_pc_monitor.agent_protocol import LogsResult


def _sample_pc_info(**overrides: object) -> dict:
    base: dict = {
        "ip": "192.168.1.10",
        "port": 9999,
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

    def _control_html(self) -> str:
        with mock.patch.object(wp, "inspect_pc", return_value=_sample_pc_info()):
            response = self.client.get("/control/192.168.1.10")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def _daily_html(self) -> str:
        with mock.patch.object(wp, "inspect_pc", return_value=_sample_pc_info()):
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
        with mock.patch.object(
            wp,
            "get_agent_logs",
            return_value=LogsResult(path="/tmp/log", truncated=False, lines=["line one"]),
        ):
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

    def test_usage_loads_action_and_usage_css(self) -> None:
        html = self._usage_html()
        self.assertIn("css/action-pages.css", html)
        self.assertIn("css/usage.css", html)
        self.assertNotIn("css/home.css", html)

    def test_js_modules_served(self) -> None:
        cases = [
            ("/static/js/core.js", "postAction"),
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
        discovered = {"192.168.1.10": {"hostname": "KidPC", "reachable": True}}
        with mock.patch.object(wp, "scan_for_servers", return_value=discovered):
            with mock.patch.object(wp, "inspect_pc", return_value=_sample_pc_info()):
                self.client.post(
                    "/scan",
                    data={"subnet": "", "csrf_token": self._csrf_from_index()},
                )
        html = self._index_html()
        self.assertIn('data-action="navigate"', html)
        self.assertIn('data-href="/control/KidPC"', html)
        self.assertNotRegex(html, _INLINE_HANDLER_RE)
        self.assertNotIn("setTimeout(", html)

    def _csrf_from_index(self) -> str:
        html = self._index_html()
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        assert match is not None, "csrf token not found on index page"
        return match.group(1)


if __name__ == "__main__":
    unittest.main()

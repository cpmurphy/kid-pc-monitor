"""Tests for install.py firewall rule reuse detection."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parent.parent
_INSTALL_PATH = _REPO_ROOT / "scripts" / "install.py"


def _load_install_module():
    spec = importlib.util.spec_from_file_location("kid_pc_install", _INSTALL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


install = _load_install_module()


class InstallFirewallTests(unittest.TestCase):
    def test_parse_firewall_rule_query_output_accepts_json(self) -> None:
        payload = {
            "program": r"C:\Python312\pythonw.exe",
            "profiles": "Private, Domain",
            "enabled": True,
        }
        result = install._parse_firewall_rule_query_output(json.dumps(payload))
        self.assertEqual(result, payload)

    def test_parse_firewall_rule_query_output_rejects_sentinel_values(self) -> None:
        for value in ("MISSING", "MISMATCH", "INCOMPLETE", ""):
            self.assertIsNone(install._parse_firewall_rule_query_output(value))

    def test_parse_firewall_rule_query_output_rejects_invalid_json(self) -> None:
        self.assertIsNone(install._parse_firewall_rule_query_output("not-json"))

    def test_find_existing_agent_firewall_rule_returns_none_on_non_windows(self) -> None:
        with mock.patch.object(install.sys, "platform", "linux"):
            self.assertIsNone(
                install.find_existing_agent_firewall_rule(r"C:\Python312\pythonw.exe")
            )

    def test_find_existing_agent_firewall_rule_parses_powershell_json(self) -> None:
        python_path = r"C:\Python312\pythonw.exe"
        payload = {
            "program": python_path,
            "profiles": "Private, Domain",
            "enabled": True,
        }
        completed = mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")

        with mock.patch.object(install.sys, "platform", "win32"), mock.patch.object(
            install.os.path, "isfile", return_value=True
        ), mock.patch.object(install.os.path, "abspath", side_effect=lambda p: p), mock.patch.object(
            install.os.path, "normpath", side_effect=lambda p: p
        ), mock.patch.object(
            install.subprocess, "run", return_value=completed
        ) as run_mock:
            result = install.find_existing_agent_firewall_rule(python_path)

        self.assertEqual(result, payload)
        run_mock.assert_called_once()

    def test_find_existing_agent_firewall_rule_returns_none_for_missing(self) -> None:
        python_path = r"C:\Python312\pythonw.exe"
        completed = mock.Mock(returncode=0, stdout="MISSING", stderr="")

        with mock.patch.object(install.sys, "platform", "win32"), mock.patch.object(
            install.os.path, "isfile", return_value=True
        ), mock.patch.object(install.os.path, "abspath", side_effect=lambda p: p), mock.patch.object(
            install.os.path, "normpath", side_effect=lambda p: p
        ), mock.patch.object(install.subprocess, "run", return_value=completed):
            self.assertIsNone(install.find_existing_agent_firewall_rule(python_path))

    def test_configure_agent_firewall_skips_prompt_when_rule_exists(self) -> None:
        existing = {
            "program": r"C:\Python312\pythonw.exe",
            "profiles": "Private, Domain",
            "enabled": True,
        }

        with mock.patch.object(
            install, "find_existing_agent_firewall_rule", return_value=existing
        ), mock.patch.object(install, "prompt_allow_public_firewall") as prompt_mock, mock.patch.object(
            install, "add_agent_firewall_rule"
        ) as add_mock:
            install.configure_agent_firewall(existing["program"])

        prompt_mock.assert_not_called()
        add_mock.assert_not_called()

    def test_configure_agent_firewall_prompts_when_rule_missing(self) -> None:
        python_path = r"C:\Python312\pythonw.exe"

        with mock.patch.object(
            install, "find_existing_agent_firewall_rule", return_value=None
        ), mock.patch.object(
            install, "prompt_allow_public_firewall", return_value=False
        ) as prompt_mock, mock.patch.object(
            install, "add_agent_firewall_rule"
        ) as add_mock:
            install.configure_agent_firewall(python_path)

        prompt_mock.assert_called_once_with()
        add_mock.assert_called_once_with(python_path, allow_public=False)


if __name__ == "__main__":
    unittest.main()

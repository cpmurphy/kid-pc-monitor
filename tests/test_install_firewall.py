"""Tests for install.py legacy firewall rule cleanup on uninstall."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parent.parent
_INSTALL_PATH = _REPO_ROOT / "scripts" / "install.py"


def _load_install_module():
    spec = importlib.util.spec_from_file_location("kid_pc_install", _INSTALL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load install module from {_INSTALL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


install = _load_install_module()


class InstallFirewallTests(unittest.TestCase):
    def test_remove_agent_firewall_rule_runs_powershell(self) -> None:
        completed = mock.Mock(returncode=0, stdout="SUCCESS: Firewall rule removed", stderr="")
        with mock.patch.object(install.subprocess, "run", return_value=completed) as run_mock:
            self.assertTrue(install.remove_agent_firewall_rule())
        run_mock.assert_called_once()
        command = run_mock.call_args.args[0]
        self.assertIn("Get-NetFirewallRule", command[-1])
        self.assertIn(install.FIREWALL_RULE_DISPLAY_NAME.replace("'", "''"), command[-1])

    def test_remove_agent_firewall_rule_handles_subprocess_error(self) -> None:
        with mock.patch.object(install.subprocess, "run", side_effect=OSError("boom")):
            self.assertFalse(install.remove_agent_firewall_rule())


if __name__ == "__main__":
    unittest.main()

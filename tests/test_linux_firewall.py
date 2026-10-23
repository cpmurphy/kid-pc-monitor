"""Tests for Linux firewall detection used by the web panel installer."""

from __future__ import annotations

import unittest
from collections.abc import Sequence
from pathlib import Path

from kid_pc_monitor import linux_firewall as fw

PORTS = (5000, 9998)


def _runner(responses: dict[tuple[str, ...], tuple[int, str]]):
    """Fake command runner; unknown commands behave as if not installed."""

    def run(cmd: Sequence[str]) -> tuple[int, str]:
        return responses.get(tuple(cmd), (127, ""))

    return run


def _reader(files: dict[Path, str]):
    def read(path: Path) -> str | None:
        return files.get(path)

    return read


UFW_ENABLED = {fw.UFW_CONF: "ENABLED=yes\nLOGLEVEL=low\n"}
UFW_DENY_DEFAULT = {fw.UFW_DEFAULTS: 'DEFAULT_INPUT_POLICY="DROP"\n'}


class NoFirewallTests(unittest.TestCase):
    def test_nothing_installed(self) -> None:
        report = fw.check_firewall(PORTS, run=_runner({}), read=_reader({}), iface="eth0")
        self.assertEqual(report.status, "none")
        self.assertIn("no changes needed", fw.format_report(report, PORTS))

    def test_ufw_installed_but_disabled(self) -> None:
        # The ufw systemd unit reports "active" even when ufw itself is disabled.
        run = _runner({("systemctl", "is-active", "ufw.service"): (0, "active\n")})
        read = _reader({fw.UFW_CONF: "ENABLED=no\n"})
        self.assertEqual(fw.check_firewall(PORTS, run=run, read=read, iface="eth0").status, "none")

    def test_firewalld_installed_but_stopped(self) -> None:
        run = _runner({("firewall-cmd", "--state"): (252, "not running\n")})
        self.assertEqual(
            fw.check_firewall(PORTS, run=run, read=_reader({}), iface="eth0").status, "none"
        )


class UfwTests(unittest.TestCase):
    def test_rules_allow_both_ports(self) -> None:
        rules = (
            "### tuple ### allow tcp 5000 0.0.0.0/0 any 0.0.0.0/0 in\n"
            "-A ufw-user-input -p tcp --dport 5000 -j ACCEPT\n"
            "### tuple ### allow any 9998 0.0.0.0/0 any 0.0.0.0/0 in\n"
        )
        read = _reader({**UFW_ENABLED, **UFW_DENY_DEFAULT, fw.UFW_USER_RULES: rules})
        report = fw.check_firewall(PORTS, run=_runner({}), read=read, iface="eth0")
        self.assertEqual((report.status, report.firewall), ("open", "ufw"))

    def test_rules_missing_one_port(self) -> None:
        rules = "### tuple ### allow tcp 5000 0.0.0.0/0 any 0.0.0.0/0 in\n"
        read = _reader({**UFW_ENABLED, **UFW_DENY_DEFAULT, fw.UFW_USER_RULES: rules})
        report = fw.check_firewall(PORTS, run=_runner({}), read=read, iface="eth0")
        self.assertEqual(report.status, "blocked")
        self.assertEqual(report.blocked_ports, (9998,))
        self.assertEqual(report.commands, (("sudo", "ufw", "allow", "9998/tcp"),))

    def test_lan_subnet_rule_allows_every_port(self) -> None:
        rules = "### tuple ### allow any any 0.0.0.0/0 any 192.168.1.0/24 in\n"
        read = _reader({**UFW_ENABLED, **UFW_DENY_DEFAULT, fw.UFW_USER_RULES: rules})
        report = fw.check_firewall(PORTS, run=_runner({}), read=read, iface="eth0")
        self.assertEqual(report.status, "open")

    def test_outbound_and_udp_rules_do_not_count(self) -> None:
        rules = (
            "### tuple ### allow tcp 5000 0.0.0.0/0 any 0.0.0.0/0 out\n"
            "### tuple ### allow udp 9998 0.0.0.0/0 any 0.0.0.0/0 in\n"
        )
        read = _reader({**UFW_ENABLED, **UFW_DENY_DEFAULT, fw.UFW_USER_RULES: rules})
        report = fw.check_firewall(PORTS, run=_runner({}), read=read, iface="eth0")
        self.assertEqual(report.blocked_ports, PORTS)

    def test_port_range_rule(self) -> None:
        rules = "### tuple ### allow tcp 4000:10000 0.0.0.0/0 any 0.0.0.0/0 in\n"
        read = _reader({**UFW_ENABLED, **UFW_DENY_DEFAULT, fw.UFW_USER_RULES: rules})
        self.assertEqual(
            fw.check_firewall(PORTS, run=_runner({}), read=read, iface="eth0").status, "open"
        )

    def test_default_accept_policy_is_open(self) -> None:
        read = _reader({**UFW_ENABLED, fw.UFW_DEFAULTS: 'DEFAULT_INPUT_POLICY="ACCEPT"\n'})
        self.assertEqual(
            fw.check_firewall(PORTS, run=_runner({}), read=read, iface="eth0").status, "open"
        )

    def test_unreadable_rules_fall_back_to_cached_sudo(self) -> None:
        status_out = (
            "Status: active\n\n"
            "To                         Action      From\n"
            "--                         ------      ----\n"
            "5000/tcp                   ALLOW       Anywhere\n"
            "9998/tcp (v6)              ALLOW       Anywhere (v6)\n"
        )
        run = _runner({("sudo", "-n", "ufw", "status"): (0, status_out)})
        read = _reader({**UFW_ENABLED, **UFW_DENY_DEFAULT})
        self.assertEqual(fw.check_firewall(PORTS, run=run, read=read, iface="eth0").status, "open")

    def test_unreadable_rules_without_sudo_is_unknown(self) -> None:
        run = _runner({("sudo", "-n", "ufw", "status"): (1, "")})
        read = _reader({**UFW_ENABLED, **UFW_DENY_DEFAULT})
        report = fw.check_firewall(PORTS, run=run, read=read, iface="eth0")
        self.assertEqual((report.status, report.firewall), ("unknown", "ufw"))
        text = fw.format_report(report, PORTS)
        self.assertIn("sudo ufw allow 5000/tcp", text)
        self.assertIn("sudo ufw allow 9998/tcp", text)
        self.assertTrue(fw._can_offer_fix(report))


class FirewalldTests(unittest.TestCase):
    def _run(self, ports_out: str, *, list_status: int = 0):
        return _runner(
            {
                ("firewall-cmd", "--state"): (0, "running\n"),
                ("firewall-cmd", "--get-zone-of-interface=eth0"): (0, "home\n"),
                ("firewall-cmd", "--zone=home", "--list-ports"): (list_status, ports_out),
            }
        )

    def test_fedora_workstation_range_is_open(self) -> None:
        run = self._run("1025-65535/tcp 1025-65535/udp\n")
        report = fw.check_firewall(PORTS, run=run, read=_reader({}), iface="eth0")
        self.assertEqual((report.status, report.firewall), ("open", "firewalld"))

    def test_blocked_ports_suggest_zone_commands(self) -> None:
        report = fw.check_firewall(PORTS, run=self._run("\n"), read=_reader({}), iface="eth0")
        self.assertEqual(report.status, "blocked")
        self.assertEqual(
            report.commands[0],
            (
                "sudo",
                "firewall-cmd",
                "--zone=home",
                "--permanent",
                "--add-port=5000/tcp",
                "--add-port=9998/tcp",
            ),
        )
        self.assertEqual(report.commands[1], ("sudo", "firewall-cmd", "--reload"))

    def test_falls_back_to_default_zone(self) -> None:
        run = _runner(
            {
                ("firewall-cmd", "--state"): (0, "running\n"),
                ("firewall-cmd", "--get-default-zone"): (0, "public\n"),
                ("firewall-cmd", "--zone=public", "--list-ports"): (0, "5000/tcp 9998/tcp\n"),
            }
        )
        self.assertEqual(
            fw.check_firewall(PORTS, run=run, read=_reader({}), iface=None).status, "open"
        )

    def test_permission_denied_is_unknown(self) -> None:
        report = fw.check_firewall(
            PORTS, run=self._run("", list_status=11), read=_reader({}), iface="eth0"
        )
        self.assertEqual((report.status, report.firewall), ("unknown", "firewalld"))
        self.assertFalse(fw._can_offer_fix(report))


class RawFirewallTests(unittest.TestCase):
    def test_active_nftables_service_is_unknown(self) -> None:
        run = _runner({("systemctl", "is-active", "nftables.service"): (0, "active\n")})
        report = fw.check_firewall(PORTS, run=run, read=_reader({}), iface="eth0")
        self.assertEqual((report.status, report.firewall), ("unknown", "nftables"))
        self.assertFalse(fw._can_offer_fix(report))


if __name__ == "__main__":
    unittest.main()

"""Tests for primary IPv4 discovery helpers."""

from __future__ import annotations

import unittest
from unittest import mock

from kid_pc_monitor import network


class NetworkTests(unittest.TestCase):
    def test_usable_ipv4_rejects_loopback_and_link_local(self) -> None:
        self.assertIsNone(network._usable_ipv4("127.0.0.1"))
        self.assertIsNone(network._usable_ipv4("169.254.1.1"))
        self.assertEqual(network._usable_ipv4("192.168.1.50"), "192.168.1.50")

    def test_linux_default_interface_from_proc(self) -> None:
        proc = """Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
"""
        self.assertEqual(network._linux_default_interface_from_proc(proc), "eth0")

    def test_linux_default_interface_skips_non_default_routes(self) -> None:
        proc = """Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
"""
        self.assertIsNone(network._linux_default_interface_from_proc(proc))

    def test_get_primary_ipv4_uses_platform_resolver(self) -> None:
        with mock.patch("kid_pc_monitor.network.platform.system", return_value="Linux"):
            with mock.patch.object(network, "_linux_primary_ipv4", return_value="10.0.0.5"):
                self.assertEqual(network.get_primary_ipv4(), "10.0.0.5")

    def test_get_primary_ipv4_falls_back_to_routing_socket(self) -> None:
        with mock.patch("kid_pc_monitor.network.platform.system", return_value="Linux"):
            with mock.patch.object(network, "_linux_primary_ipv4", return_value=None):
                with mock.patch.object(
                    network, "_ipv4_from_routing_socket", return_value="192.168.8.113"
                ):
                    self.assertEqual(network.get_primary_ipv4(), "192.168.8.113")

    def test_get_local_ip_defaults_to_loopback(self) -> None:
        with mock.patch.object(network, "get_primary_ipv4", return_value=None):
            self.assertEqual(network.get_local_ip(), "127.0.0.1")

    def test_routing_socket_uses_test_net_address(self) -> None:
        with mock.patch.object(network.socket, "socket") as mock_socket_cls:
            mock_sock = mock_socket_cls.return_value.__enter__.return_value
            mock_sock.getsockname.return_value = ("192.168.1.10", 0)
            ip = network._ipv4_from_routing_socket()
            mock_sock.connect.assert_called_once_with(
                (network._ROUTING_PROBE_HOST, network._ROUTING_PROBE_PORT)
            )
            self.assertEqual(ip, "192.168.1.10")


if __name__ == "__main__":
    unittest.main()

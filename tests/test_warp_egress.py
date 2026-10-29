"""Cloudflare WARP egress is optional and scoped to WG client traffic."""
import unittest
from unittest.mock import patch

from managers.wireguard_manager import WireGuardManager


class RecordingSSH:
    def __init__(self):
        self.uploads = {}
        self.commands = []

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return "", "", 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        return "", "", 0


class WireGuardWarpEgressTests(unittest.TestCase):
    def test_start_script_routes_only_client_subnet_through_warp_when_attached(self):
        ssh = RecordingSSH()
        manager = WireGuardManager(ssh)
        with patch("managers.wireguard_manager.time.sleep", return_value=None):
            manager._upload_start_script("51820")

        script = ssh.uploads["/tmp/_wg_start.sh"]
        self.assertIn("# Optional Cloudflare WARP egress", script)
        self.assertIn("ip -4 rule add priority 210 from 10.8.2.0/24 table 51820", script)
        self.assertIn("default via 172.29.173.2", script)
        self.assertIn("iptables -t nat -A POSTROUTING -s 10.8.2.0/24 -o \"$WARP_IF\" -j MASQUERADE", script)
        self.assertEqual(ssh.commands[-1], "docker restart amnezia-wireguard")

    def test_warp_routing_is_conditional_on_gateway_network_interface(self):
        ssh = RecordingSSH()
        manager = WireGuardManager(ssh)
        with patch("managers.wireguard_manager.time.sleep", return_value=None):
            manager._upload_start_script("51820")
        script = ssh.uploads["/tmp/_wg_start.sh"]
        self.assertIn("if [ -n \"$WARP_IF\" ]; then", script)
        self.assertIn("WARP_IF=$(ip -o -4 addr show", script)


if __name__ == "__main__":
    unittest.main()

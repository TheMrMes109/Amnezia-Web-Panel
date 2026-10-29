"""Cloudflare WARP egress is optional and scoped to WG client traffic."""
import unittest
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

from managers.wireguard_manager import WireGuardManager
from managers.awg_manager import AWGManager
from managers.wireguard_exit_manager import WireGuardExitManager


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
        self.assertIn("ip -6 rule add priority 210 iif wg0 prohibit", script)
        self.assertEqual(ssh.commands[-1], "docker restart amnezia-wireguard")

    def test_awg_start_script_has_optional_warp_route(self):
        script = AWGManager(None)._render_start_script("awg")
        self.assertIn("# ---- Optional Cloudflare WARP egress for VPN clients ----", script)
        self.assertIn('ip -4 rule add priority 210 from "$SUBNET" table 51820', script)
        self.assertIn('iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WARP_IF" -j MASQUERADE', script)

    def test_awg_ipv6_uses_warp_when_available_or_fails_closed(self):
        script = AWGManager(None)._render_start_script("awg")
        self.assertIn('ip -6 route replace default via fd42:173::2 dev "$WARP_IF" table 51822', script)
        self.assertIn('ip -6 rule add priority 210 from "$SUBNET6" prohibit', script)

    def test_wireguard_exit_hooks_and_warp_block_coexist(self):
        ssh = RecordingSSH()
        original = """#!/bin/bash
echo "WireGuard container startup"
# Start WireGuard
if [ -f /opt/amnezia/wireguard/wg0.conf ]; then wg-quick up /opt/amnezia/wireguard/wg0.conf; fi
tail -f /dev/null
"""
        config = "[Interface]\\nAddress = 10.8.2.1/24\\n"
        def run_sudo(command, timeout=60):
            ssh.commands.append(command)
            if "cat /opt/amnezia/start.sh" in command:
                return original, "", 0
            if "cat /opt/amnezia/wireguard/wg0.conf" in command:
                return config, "", 0
            return "", "", 0
        ssh.run_sudo_command = run_sudo

        WireGuardExitManager(ssh)._write_start_script("wireguard")

        script = ssh.uploads["/tmp/_amnz_wg_start.sh"]
        self.assertIn("# ---- Exit-node link (panel-managed; driven by", script)
        self.assertIn("# ---- Optional Cloudflare WARP egress for VPN clients ----", script)
        self.assertIn("ip -4 rule add priority 210 from 10.8.2.1/24 table 51820", script)

    def test_warp_routing_is_conditional_on_gateway_network_interface(self):
        ssh = RecordingSSH()
        manager = WireGuardManager(ssh)
        with patch("managers.wireguard_manager.time.sleep", return_value=None):
            manager._upload_start_script("51820")
        script = ssh.uploads["/tmp/_wg_start.sh"]
        self.assertIn("if [ -n \"$WARP_IF\" ]; then", script)
        self.assertIn("WARP_IF=$(ip -o -4 addr show", script)


class WarpTemplateTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_gateway_entrypoint_parses_as_bash(self):
        template = Path(__file__).resolve().parents[1] / "protocol_templates" / "cloudflare-warp" / "entrypoint.sh"
        result = subprocess.run(["bash", "-n", str(template)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

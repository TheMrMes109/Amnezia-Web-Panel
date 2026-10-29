"""Exit-node routing adapter for the panel's standard WireGuard container.

The transit tunnel is plain WireGuard (compatible with an un-obfuscated exit
node). This adapter reuses the tested policy-routing/kill-switch implementation
from AWGManager while preserving WireGuardManager's own container startup script.
"""
from managers.awg_manager import AWGManager, AWG_DEFAULTS


class WireGuardExitManager(AWGManager):
    """AWGManager's exit-link operations adapted to the standard wg0 container."""

    WG_CONTAINER = "amnezia-wireguard"
    WG_CONFIG = "/opt/amnezia/wireguard/wg0.conf"

    def _base_protocol(self, protocol_type):
        return "wireguard"

    def _instance_index(self, protocol_type):
        return 1

    def _container_name(self, protocol_type):
        return self.WG_CONTAINER

    def _config_path(self, protocol_type):
        return self.WG_CONFIG

    def _config_path_candidates(self, protocol_type):
        return [self.WG_CONFIG]

    def _resolve_config_path(self, protocol_type):
        return self.WG_CONFIG

    def _wg_binary(self, protocol_type):
        return "wg"

    def _quick_binary(self, protocol_type):
        return "wg-quick"

    def _interface_name(self, protocol_type, config_path=None):
        return "wg0"

    def _get_server_config(self, protocol_type):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.WG_CONTAINER} cat {self.WG_CONFIG}"
        )
        if code != 0 or not out.strip():
            raise RuntimeError(f"Could not read WireGuard server config: {err or out}")
        return out

    def _write_start_script(self, protocol_type, config_path=None):
        """Keep exit-link hooks and optional WARP client routing in start.sh."""
        config_path = config_path or self.WG_CONFIG
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.WG_CONTAINER} cat /opt/amnezia/start.sh"
        )
        if code != 0 or not out.strip():
            raise RuntimeError(f"Could not read WireGuard start script: {err or out}")
        script = out
        changed = False

        exit_marker = "# ---- Exit-node link (panel-managed; driven by"
        if exit_marker not in script:
            start_marker = "# Start WireGuard"
            if start_marker not in script:
                raise RuntimeError("WireGuard start script layout is not recognized; refusing to overwrite it")
            functions = self._exit_shell_functions(
                config_path, "wg-quick",
                f"{AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}"
            )
            script = script.replace(
                start_marker,
                functions
                + '\n# Install the kill-switch before wg0 accepts client traffic.\n'
                + '[ -f "$EXIT_CONF" ] && x_killswitch_on\n\n'
                + start_marker,
                1,
            )
            wg_up = f"if [ -f {config_path} ]; then wg-quick up {config_path}; fi"
            if wg_up not in script:
                raise RuntimeError("WireGuard start command not found; refusing to install partial exit hooks")
            script = script.replace(wg_up, wg_up + '\n[ -f "$EXIT_CONF" ] && x_exit_sync', 1)
            changed = True

        warp_marker = "# ---- Optional Cloudflare WARP egress for VPN clients ----"
        if warp_marker not in script:
            subnet_ip = self._get_subnet_ip(protocol_type)
            subnet_cidr = self._get_subnet_cidr(protocol_type)
            warp_block = f'''
{warp_marker}
WARP_IF=$(ip -o -4 addr show | awk '$4 ~ /^172.29.173\\./ {{print $2; exit}}')
if [ -n "$WARP_IF" ]; then
    ip -4 route replace 172.29.173.0/24 dev "$WARP_IF" table 51820
    ip -4 route replace default via 172.29.173.2 dev "$WARP_IF" table 51820
    while ip -4 rule del priority 210 from {subnet_ip}/{subnet_cidr} table 51820 2>/dev/null; do :; done
    ip -4 rule add priority 210 from {subnet_ip}/{subnet_cidr} table 51820
fi
'''
            tail_marker = "tail -f /dev/null"
            if tail_marker not in script:
                raise RuntimeError("WireGuard start script tail marker not found; refusing to add WARP routing")
            script = script.replace(tail_marker, warp_block + '\n' + tail_marker, 1)
            changed = True

        if not changed:
            return
        self.ssh.upload_file(script, "/tmp/_amnz_wg_start.sh")
        out, err, code = self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_wg_start.sh {self.WG_CONTAINER}:/opt/amnezia/start.sh "
            f"&& docker exec -i {self.WG_CONTAINER} chmod 700 /opt/amnezia/start.sh"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_wg_start.sh")
        if code != 0:
            raise RuntimeError(f"Could not install WireGuard start hooks: {err or out}")

    def _get_subnet_ip(self, protocol_type):
        try:
            for line in self._get_server_config(protocol_type).splitlines():
                if line.strip().startswith("Address") and "=" in line:
                    return line.split("=", 1)[1].strip().split(",")[0].split("/")[0].strip()
        except Exception:
            pass
        return "10.8.1.1"

    def _get_subnet_cidr(self, protocol_type):
        try:
            for line in self._get_server_config(protocol_type).splitlines():
                if line.strip().startswith("Address") and "=" in line:
                    address = line.split("=", 1)[1].strip().split(",")[0].strip()
                    if "/" in address:
                        return address.rsplit("/", 1)[1]
        except Exception:
            pass
        return str(AWG_DEFAULTS["subnet_cidr"])

"""Plain WireGuard transit endpoint kept alongside the obfuscated AWG exit.

It intentionally uses a separate container, port, config, peer table and subnet:
a standard WireGuard entry must never be sent to the obfuscated endpoint.
"""
from managers.exit_manager import ExitManager


class PlainWireGuardExitManager(ExitManager):
    """Second, un-obfuscated transit endpoint for standard WireGuard entries."""

    CONTAINER_NAME = "amnezia-exit-wg"
    CONFIG_DIR = "/opt/amnezia/exit-wg"
    CONFIG_PATH = "/opt/amnezia/exit-wg/transit0.conf"
    PEERS_TABLE = "/opt/amnezia/exit-wg/peersTable"
    PRIVATE_KEY_PATH = "/opt/amnezia/exit-wg/wireguard_server_private_key.key"
    PUBLIC_KEY_PATH = "/opt/amnezia/exit-wg/wireguard_server_public_key.key"

    PLAIN_PORT = "55521"
    PLAIN_SUBNET = "10.10.0.0/24"

    def _render_start_script(self, protocol_type=None, config_path=None):
        # _start_script_body reads the actual subnet from this endpoint's config.
        return self._start_script_body(
            self.CONFIG_PATH,
            "awg-quick",
            "",
            self.PLAIN_SUBNET,
            self._bwlimits_path(),
            extra_blocks=(self._mss_clamp_body(self.INTERFACE),),
        )

    def add_peer(self, peer_id, name, public_key):
        # Provision the compatible endpoint on demand; do not modify the
        # existing obfuscated amnezia-exit container or its peers.
        if not self.check_protocol_installed(self.PROTOCOL):
            result = self.install_protocol()
            if result.get("status") != "success":
                raise RuntimeError(result.get("message", "Could not install plain WireGuard exit endpoint"))
        if not self.check_container_running(self.PROTOCOL):
            raise RuntimeError("Plain WireGuard exit endpoint is not running")
        return super().add_peer(peer_id, name, public_key)

    def install_protocol(self, protocol_type="exit", port=None, subnet=None,
                         obfuscation=False, **kwargs):
        """Install a plain WG-compatible endpoint without touching the AWG one."""
        if obfuscation:
            return {
                "status": "error",
                "message": "The WireGuard-compatible endpoint cannot use AmneziaWG obfuscation",
            }
        result = super().install_protocol(
            protocol_type=protocol_type,
            port=port or self.PLAIN_PORT,
            subnet=subnet or self.PLAIN_SUBNET,
            obfuscation=False,
            **kwargs,
        )
        if result.get("status") == "success":
            result["endpoint_kind"] = "wireguard"
            result["obfuscation"] = False
        return result

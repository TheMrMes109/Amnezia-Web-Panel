"""WireGuardTo: standard WireGuard peers routed exclusively through an AWG Exit Link."""
import shlex

from managers.wireguard_manager import WireGuardManager, generate_wg_keypair, generate_psk
from managers.awg_manager import AWGManager, EXIT_CONF

WGTO_PORT = 51821
WGTO_SUBNET = "10.77.77.0/24"
WGTO_ADDRESS = "10.77.77.1/24"
WGTO_TABLE = 201
WGTO_PREF = 180
WGTO_DIR = "/opt/amnezia/wireguardto"
WGTO_CONFIG = f"{WGTO_DIR}/wgto0.conf"
WGTO_CLIENTS = f"{WGTO_DIR}/clientsTable"
WGTO_BWLIMITS = f"{WGTO_DIR}/bwlimits"
AWG_CANDIDATES = (
    ("awg", "amnezia-awg"),
    ("awg2", "amnezia-awg2"),
    ("awg3", "amnezia-awg3"),
    ("awg_legacy", "amnezia-awg-legacy"),
)


class WireGuardToManager(WireGuardManager):
    """Peer lifecycle compatible with WireGuardManager, but hosted by AWG."""

    PROTOCOL = "wireguardto"
    CONTAINER_NAME = "amnezia-awg"
    CONFIG_PATH = WGTO_CONFIG
    KEY_DIR = WGTO_DIR
    CLIENTS_TABLE_PATH = WGTO_CLIENTS
    BWLIMITS_PATH = WGTO_BWLIMITS
    INTERFACE = "wgto0"

    def __init__(self, ssh_manager):
        super().__init__(ssh_manager)
        self.awg_protocol = "awg"
        self.CONTAINER_NAME = "amnezia-awg"
        self._discover_awg()

    def _discover_awg(self):
        """Find the AWG container that already owns the WireGuardTo config."""
        out, _, code = self.ssh.run_sudo_command("docker ps --format '{{.Names}}'")
        if code != 0:
            return
        names = set((out or "").split())
        for proto, name in AWG_CANDIDATES:
            if name not in names:
                continue
            _, _, installed_code = self.ssh.run_sudo_command(
                f"docker exec {shlex.quote(name)} test -s {WGTO_CONFIG}"
            )
            if installed_code == 0:
                self.awg_protocol, self.CONTAINER_NAME = proto, name
                return
        for proto, name in AWG_CANDIDATES:
            if name in names:
                self.awg_protocol, self.CONTAINER_NAME = proto, name
                return

    def _select_awg_with_exit(self, target_protocol=None):
        out, err, code = self.ssh.run_sudo_command("docker ps --format '{{.Names}}'")
        if code != 0:
            raise RuntimeError(err or "Cannot inspect running Docker containers")
        names = set((out or "").split())
        candidates = [(p, n) for p, n in AWG_CANDIDATES
                      if n in names and (not target_protocol or p == target_protocol)]
        if not candidates:
            raise RuntimeError(f"Selected AmneziaWG instance '{target_protocol}' is not running")
        linked = []
        for proto, name in candidates:
            _, _, check_code = self.ssh.run_sudo_command(
                f"docker exec {shlex.quote(name)} sh -c "
                + shlex.quote(f"test -s {EXIT_CONF} && ip link show exit0 >/dev/null 2>&1")
            )
            if check_code == 0:
                linked.append((proto, name))
        if len(linked) != 1:
            if target_protocol:
                raise RuntimeError(
                    f"Selected {target_protocol} has no active Exit Link. "
                    "Connect this AmneziaWG instance to an Exit Node first."
                )
            raise RuntimeError(
                "Select a specific AmneziaWG instance with an active Exit Link for WireGuardTo."
            )
        self.awg_protocol, self.CONTAINER_NAME = linked[0]
        return self.CONTAINER_NAME

    def check_protocol_installed(self):
        _, _, code = self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} test -s {WGTO_CONFIG}"
        )
        return code == 0

    def check_container_running(self):
        if not self.check_protocol_installed():
            return False
        _, _, code = self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} wg show wgto0"
        )
        return code == 0

    def get_server_status(self):
        info = super().get_server_status()
        info["container_name"] = self.CONTAINER_NAME
        return info

    def _put_file(self, content, remote_tmp, destination):
        self.ssh.upload_file(content, remote_tmp)
        out, err, code = self.ssh.run_sudo_command(
            f"docker cp {shlex.quote(remote_tmp)} "
            f"{shlex.quote(self.CONTAINER_NAME + ':' + destination)}"
        )
        self.ssh.run_command(f"rm -f {shlex.quote(remote_tmp)}")
        if code != 0:
            raise RuntimeError(err or out or f"Could not write {destination}")

    def _get_server_public_key(self):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} cat {WGTO_DIR}/wireguard_server_public_key.key"
        )
        if code != 0:
            raise RuntimeError(err or "WireGuardTo public key is unavailable")
        return out.strip()

    def _get_server_psk(self):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} cat {WGTO_DIR}/wireguard_psk.key"
        )
        if code != 0:
            raise RuntimeError(err or "WireGuardTo PSK is unavailable")
        return out.strip()

    def _get_next_ip(self):
        used = set(self._get_used_ips()) | set(self._get_reserved_ips())
        for host in range(2, 255):
            candidate = f"10.77.77.{host}"
            if candidate not in used:
                return candidate
        raise RuntimeError("WireGuardTo subnet has no free client addresses")

    def add_client(self, client_name, server_host, public_port=None):
        result = super().add_client(client_name, server_host, public_port=public_port)
        result["config"] = result["config"].replace(
            "AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/0"
        ).replace("MTU = 1420", "MTU = 1280")
        return result

    def get_client_config(self, client_id, server_host, port=None, public_port=None):
        config = super().get_client_config(
            client_id, server_host, port=port, public_port=public_port
        )
        return config.replace("AllowedIPs = 0.0.0.0/0, ::/0",
                              "AllowedIPs = 0.0.0.0/0").replace("MTU = 1420", "MTU = 1280")

    def _write_awg_start_script(self):
        awg = AWGManager(self.ssh)
        awg._write_start_script(
            self.awg_protocol,
            config_path=awg._resolve_config_path(self.awg_protocol),
        )

    def _apply_live(self):
        script = f"""#!/bin/bash
set -e
ip -4 route replace blackhole default metric 1000 table {WGTO_TABLE}
while ip -4 rule del pref {WGTO_PREF} from {WGTO_SUBNET} table {WGTO_TABLE} 2>/dev/null; do :; done
ip -4 rule add pref {WGTO_PREF} from {WGTO_SUBNET} table {WGTO_TABLE}
wg-quick down {WGTO_CONFIG} 2>/dev/null || true
wg-quick up {WGTO_CONFIG}
iptables -C INPUT -i wgto0 -j ACCEPT 2>/dev/null || iptables -A INPUT -i wgto0 -j ACCEPT
iptables -C FORWARD -i wgto0 -o exit0 -s {WGTO_SUBNET} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wgto0 -o exit0 -s {WGTO_SUBNET} -j ACCEPT
iptables -t nat -C POSTROUTING -s {WGTO_SUBNET} -o exit0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {WGTO_SUBNET} -o exit0 -j MASQUERADE
ip6tables -C FORWARD -i wgto0 -j DROP 2>/dev/null || ip6tables -I FORWARD 1 -i wgto0 -j DROP
while ip -6 rule del pref {WGTO_PREF} iif wgto0 prohibit 2>/dev/null; do :; done
ip -6 rule add pref {WGTO_PREF} iif wgto0 prohibit 2>/dev/null || true
if ip link show exit0 >/dev/null 2>&1; then
  ip -4 route replace default dev exit0 metric 10 table {WGTO_TABLE}
else
  ip -4 route replace blackhole default metric 1000 table {WGTO_TABLE}
fi
"""
        self._put_file(script, "/tmp/_wireguardto_apply.sh", "/tmp/_wireguardto_apply.sh")
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} bash /tmp/_wireguardto_apply.sh",
            timeout=60,
        )
        if code != 0:
            raise RuntimeError(err or out or "WireGuardTo could not be started")
        return out

    def _install_host_forwarder(self, port):
        script = f"""#!/bin/bash
set -u
HOST_PORT={int(port)}
CONTAINER_PORT={int(port)}
CONTAINER_NAME={shlex.quote(self.CONTAINER_NAME)}
clean_rules() {{
  iptables -t nat -S PREROUTING 2>/dev/null | grep -F -- '--comment WireGuardTo' | sed 's/^-A /-D /' | while IFS= read -r rule; do eval "iptables -t nat $rule" 2>/dev/null || true; done
  iptables -S FORWARD 2>/dev/null | grep -F -- '--comment WireGuardTo' | sed 's/^-A /-D /' | while IFS= read -r rule; do eval "iptables $rule" 2>/dev/null || true; done
  iptables -S DOCKER-USER 2>/dev/null | grep -F -- '--comment WireGuardTo' | sed 's/^-A /-D /' | while IFS= read -r rule; do eval "iptables $rule" 2>/dev/null || true; done
}}
clean_rules
IP="$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' "$CONTAINER_NAME" 2>/dev/null || true)"
[ -n "$IP" ] || exit 0
iptables -t nat -A PREROUTING -p udp --dport "$HOST_PORT" -m comment --comment WireGuardTo -j DNAT --to-destination "$IP:$CONTAINER_PORT"
iptables -I FORWARD 1 -p udp -d "$IP" --dport "$CONTAINER_PORT" -m comment --comment WireGuardTo -j ACCEPT
iptables -I DOCKER-USER 1 -p udp -d "$IP" --dport "$CONTAINER_PORT" -m comment --comment WireGuardTo -j ACCEPT 2>/dev/null || true
"""
        service = """[Unit]
Description=Refresh WireGuardTo UDP forwarding
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wireguardto-port-forward.sh
"""
        timer = """[Unit]
Description=Keep WireGuardTo UDP forwarding bound to the current AWG container IP

[Timer]
OnBootSec=10s
OnUnitActiveSec=20s
Unit=wireguardto-port-forward.service

[Install]
WantedBy=timers.target
"""
        self.ssh.upload_file(script, "/tmp/_wireguardto-port-forward.sh")
        self.ssh.upload_file(service, "/tmp/wireguardto-port-forward.service")
        self.ssh.upload_file(timer, "/tmp/wireguardto-port-forward.timer")
        commands = (
            "install -m 0755 /tmp/_wireguardto-port-forward.sh /usr/local/sbin/wireguardto-port-forward.sh",
            "install -m 0644 /tmp/wireguardto-port-forward.service /etc/systemd/system/wireguardto-port-forward.service",
            "install -m 0644 /tmp/wireguardto-port-forward.timer /etc/systemd/system/wireguardto-port-forward.timer",
            "rm -f /tmp/_wireguardto-port-forward.sh /tmp/wireguardto-port-forward.service /tmp/wireguardto-port-forward.timer",
            "systemctl daemon-reload",
            "systemctl enable --now wireguardto-port-forward.timer",
            "systemctl start wireguardto-port-forward.service",
        )
        for command in commands:
            out, err, code = self.ssh.run_sudo_command(command, timeout=60)
            if code != 0:
                raise RuntimeError(err or out or f"Host UDP forwarder setup failed: {command}")

    def install_protocol(self, port=None, awg_protocol=None):
        port = int(port or WGTO_PORT)
        if not 1 <= port <= 65535:
            raise RuntimeError("WireGuardTo UDP port must be between 1 and 65535")
        self._select_awg_with_exit(awg_protocol)
        if self.check_protocol_installed():
            raise RuntimeError("WireGuardTo is already installed")
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} sh -c "
            + shlex.quote("command -v wg-quick >/dev/null 2>&1 || apk add --no-cache wireguard-tools iproute2 iptables")
        )
        if code != 0:
            raise RuntimeError(err or out or "Could not install standard WireGuard tools in AWG container")
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} mkdir -p {WGTO_DIR}"
        )
        if code != 0:
            raise RuntimeError(err or out or "Could not create WireGuardTo state directory")
        private_key, public_key = generate_wg_keypair()
        psk = generate_psk()
        config = f"""[Interface]
Address = {WGTO_ADDRESS}
ListenPort = {port}
PrivateKey = {private_key}
MTU = 1280
Table = off
"""
        self._put_file(private_key + "\n", "/tmp/_wgto_private", f"{WGTO_DIR}/wireguard_server_private_key.key")
        self._put_file(public_key + "\n", "/tmp/_wgto_public", f"{WGTO_DIR}/wireguard_server_public_key.key")
        self._put_file(psk + "\n", "/tmp/_wgto_psk", f"{WGTO_DIR}/wireguard_psk.key")
        self._put_file(config, "/tmp/_wgto_config", WGTO_CONFIG)
        self._put_file("[]\n", "/tmp/_wgto_clients", WGTO_CLIENTS)
        self.ssh.run_sudo_command(
            f"docker exec {shlex.quote(self.CONTAINER_NAME)} chmod 600 {WGTO_DIR}/*"
        )
        self._write_awg_start_script()
        self._install_host_forwarder(port)
        self._apply_live()
        return {
            "status": "success",
            "message": "WireGuardTo is listening and routed only through the AWG Exit Link.",
            "port": str(port),
            "container_name": self.CONTAINER_NAME,
            "awg_protocol": self.awg_protocol,
            "public_key": public_key,
            "subnet": WGTO_SUBNET,
        }

    def remove_container(self, protocol_type=None):
        if self.CONTAINER_NAME:
            cleanup = f"""#!/bin/bash
while ip -4 rule del pref {WGTO_PREF} from {WGTO_SUBNET} table {WGTO_TABLE} 2>/dev/null; do :; done
while ip -6 rule del pref {WGTO_PREF} iif wgto0 prohibit 2>/dev/null; do :; done
wg-quick down {WGTO_CONFIG} 2>/dev/null || true
iptables -D INPUT -i wgto0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i wgto0 -o exit0 -s {WGTO_SUBNET} -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s {WGTO_SUBNET} -o exit0 -j MASQUERADE 2>/dev/null || true
ip6tables -D FORWARD -i wgto0 -j DROP 2>/dev/null || true
ip -4 route flush table {WGTO_TABLE} 2>/dev/null || true
rm -rf {WGTO_DIR}
"""
            self._put_file(cleanup, "/tmp/_wireguardto_remove.sh", "/tmp/_wireguardto_remove.sh")
            self.ssh.run_sudo_command(
                f"docker exec {shlex.quote(self.CONTAINER_NAME)} bash /tmp/_wireguardto_remove.sh",
                timeout=60,
            )
            self._write_awg_start_script()
        commands = (
            "systemctl disable --now wireguardto-port-forward.timer 2>/dev/null || true",
            "systemctl stop wireguardto-port-forward.service 2>/dev/null || true",
            "rm -f /usr/local/sbin/wireguardto-port-forward.sh /etc/systemd/system/wireguardto-port-forward.service /etc/systemd/system/wireguardto-port-forward.timer",
            "systemctl daemon-reload",
            "iptables -t nat -S PREROUTING 2>/dev/null | grep -F -- '--comment WireGuardTo' | sed 's/^-A /-D /' | while IFS= read -r rule; do eval \"iptables -t nat $rule\" 2>/dev/null || true; done",
            "iptables -S FORWARD 2>/dev/null | grep -F -- '--comment WireGuardTo' | sed 's/^-A /-D /' | while IFS= read -r rule; do eval \"iptables $rule\" 2>/dev/null || true; done",
            "iptables -S DOCKER-USER 2>/dev/null | grep -F -- '--comment WireGuardTo' | sed 's/^-A /-D /' | while IFS= read -r rule; do eval \"iptables $rule\" 2>/dev/null || true; done",
        )
        for command in commands:
            self.ssh.run_sudo_command(command, timeout=60)
        return True

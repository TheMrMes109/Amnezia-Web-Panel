"""Remote Cloudflare WARP egress gateway for WireGuard/AmneziaWG servers.

The WARP tunnel is isolated in its own container. VPN client traffic is
policy-routed to this gateway from WG/AWG containers, while their public UDP
listeners and SSH management traffic keep the host's ordinary route.
"""
import os
import time


WARP_NETWORK = "amnezia-warp-net"
WARP_CONTAINER = "amnezia-warp-gateway"
WARP_IMAGE = "amnezia-warp-gateway:local"
WARP_SUBNET = "172.29.173.0/24"
WARP_GATEWAY_IP = "172.29.173.2"
WARP_NETWORK_GATEWAY = "172.29.173.1"
WARP_ROOT = "/opt/amnezia/warp-gateway"


class WarpGatewayManager:
    def __init__(self, ssh_manager):
        self.ssh = ssh_manager

    def _run(self, command, timeout=60):
        out, err, code = self.ssh.run_sudo_command(command, timeout=timeout)
        if code != 0:
            raise RuntimeError((err or out or "Cloudflare WARP gateway command failed").strip())
        return out

    def _template(self, filename):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "protocol_templates", "cloudflare-warp", filename)
        with open(path, "r", encoding="utf-8") as source:
            return source.read()

    def network_exists(self):
        _out, _err, code = self.ssh.run_sudo_command(
            f"docker network inspect {WARP_NETWORK} >/dev/null 2>&1"
        )
        return code == 0

    def ensure_gateway(self, timeout=180):
        """Build and start the isolated WARP gateway, waiting for a live tunnel."""
        self._run(f"mkdir -p {WARP_ROOT}/state")
        self._run(
            f"docker network inspect {WARP_NETWORK} >/dev/null 2>&1 || "
            f"docker network create --driver bridge --subnet {WARP_SUBNET} "
            f"--gateway {WARP_NETWORK_GATEWAY} {WARP_NETWORK}",
            timeout=30,
        )

        _out, _err, exists_code = self.ssh.run_sudo_command(
            f"docker inspect {WARP_CONTAINER} >/dev/null 2>&1"
        )
        if exists_code != 0:
            self.ssh.upload_file_sudo(self._template("Dockerfile"), f"{WARP_ROOT}/Dockerfile")
            self.ssh.upload_file_sudo(self._template("entrypoint.sh"), f"{WARP_ROOT}/entrypoint.sh")
            self._run(f"docker build --pull -t {WARP_IMAGE} {WARP_ROOT}", timeout=600)
            self._run(
                f"docker run -d --restart unless-stopped "
                f"--device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN "
                f"--sysctl net.ipv4.ip_forward=1 "
                f"--network {WARP_NETWORK} --ip {WARP_GATEWAY_IP} "
                f"-e WARP_SUBNET={WARP_SUBNET} "
                f"-v {WARP_ROOT}/state:/var/lib/cloudflare-warp "
                f"--name {WARP_CONTAINER} {WARP_IMAGE}",
                timeout=60,
            )
        else:
            state, _state_err, state_code = self.ssh.run_sudo_command(
                f"docker inspect -f '{{{{.State.Running}}}}' {WARP_CONTAINER}", timeout=30
            )
            if state_code == 0 and state.strip().lower() == "true":
                status, _status_err, status_code = self.ssh.run_sudo_command(
                    f"docker exec {WARP_CONTAINER} warp-cli --accept-tos status 2>/dev/null", timeout=20
                )
                import re
                if status_code != 0 or not re.search(
                    r"(^|\s)Connected($|\s)", status, re.IGNORECASE
                ):
                    self._run(f"docker restart {WARP_CONTAINER}", timeout=60)
            else:
                self._run(f"docker start {WARP_CONTAINER}", timeout=30)

        wait_script = (
            f"for i in $(seq 1 {int(timeout)}); do "
            f"if docker exec {WARP_CONTAINER} warp-cli --accept-tos status 2>/dev/null "
            f"| grep -Eqi '(^|[[:space:]])Connected([[:space:]]|$)' && "
            f"docker exec {WARP_CONTAINER} ip link show CloudflareWARP >/dev/null 2>&1; "
            f"then exit 0; fi; sleep 1; done; "
            f"docker logs --tail 80 {WARP_CONTAINER} 2>&1; exit 1"
        )
        self._run(wait_script, timeout=timeout + 20)
        return {"status": "connected", "container": WARP_CONTAINER, "network": WARP_NETWORK}

    def attach_container(self, container_name):
        """Attach a WG/AWG container to the WARP transit network idempotently."""
        self._run(
            f"docker network connect {WARP_NETWORK} {container_name} >/dev/null 2>&1 || true",
            timeout=30,
        )
        out = self._run(
            f"docker inspect -f '{{{{json .NetworkSettings.Networks}}}}' {container_name}",
            timeout=30,
        )
        if WARP_NETWORK not in out:
            raise RuntimeError(f"{container_name} is not attached to {WARP_NETWORK}")
        return True

    def detach_container(self, container_name):
        self._run(
            f"docker network disconnect {WARP_NETWORK} {container_name} >/dev/null 2>&1 || true",
            timeout=30,
        )
        return True

    def remove_gateway(self):
        """Remove the gateway and transit network; keep registration state for reuse."""
        self._run(f"docker rm -f {WARP_CONTAINER} >/dev/null 2>&1 || true", timeout=30)
        self._run(f"docker network rm {WARP_NETWORK} >/dev/null 2>&1 || true", timeout=30)
        return {"status": "disconnected", "container": WARP_CONTAINER}

#!/bin/bash
set -Eeuo pipefail

WARP_SUBNET="${WARP_SUBNET:-172.29.173.0/24}"
WARP_IF=""

mkdir -p /var/lib/cloudflare-warp /run/dbus
dbus-daemon --system --fork 2>/dev/null || true
warp-svc >/var/log/warp-svc.log 2>&1 &
WARP_PID=$!
trap 'kill "$WARP_PID" 2>/dev/null || true' EXIT

for attempt in $(seq 1 60); do
    if warp-cli --accept-tos status >/tmp/warp-status.txt 2>&1; then
        break
    fi
    sleep 1
done

if ! warp-cli --accept-tos status >/tmp/warp-status.txt 2>&1; then
    cat /tmp/warp-status.txt >&2 || true
    echo "Cloudflare WARP service did not become ready" >&2
    exit 1
fi

if grep -Eqi 'registration missing|not registered|not enrolled' /tmp/warp-status.txt; then
    warp-cli --accept-tos registration new
fi
warp-cli --accept-tos mode warp
warp-cli --accept-tos connect

for attempt in $(seq 1 90); do
    warp-cli --accept-tos status >/tmp/warp-status.txt 2>&1 || true
    WARP_IF=$(ip -o link show | awk -F': ' '$2 ~ /CloudflareWARP|warp/ {gsub(/@.*/, "", $2); print $2; exit}')
    if grep -Eqi '(^|[[:space:]])Connected([[:space:]]|$)' /tmp/warp-status.txt && [ -n "$WARP_IF" ]; then
        break
    fi
    sleep 1
done

if [ -z "$WARP_IF" ]; then
    cat /tmp/warp-status.txt >&2 || true
    echo "Cloudflare WARP interface was not created" >&2
    exit 1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip route replace default dev "$WARP_IF" table 51821
while ip rule del priority 210 from "$WARP_SUBNET" table 51821 2>/dev/null; do :; done
ip rule add priority 210 from "$WARP_SUBNET" table 51821
iptables -C FORWARD -i eth0 -o "$WARP_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o "$WARP_IF" -j ACCEPT
iptables -C FORWARD -i "$WARP_IF" -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WARP_IF" -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -s "$WARP_SUBNET" -o "$WARP_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$WARP_SUBNET" -o "$WARP_IF" -j MASQUERADE

echo "Cloudflare WARP gateway ready on $WARP_IF"
tail -f /dev/null

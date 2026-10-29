#!/bin/bash
set -Eeuo pipefail

WARP_SUBNET="${WARP_SUBNET:-172.29.173.0/24}"
WARP_SUBNET6="${WARP_SUBNET6:-fd42:173::/64}"
WARP_IPV6_ENABLED="${WARP_IPV6_ENABLED:-0}"
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
ip route replace 172.29.173.0/24 dev eth0 table 51821
ip route replace default dev "$WARP_IF" table 51821
while ip rule del priority 210 from "$WARP_SUBNET" table 51821 2>/dev/null; do :; done
ip rule add priority 210 from "$WARP_SUBNET" table 51821
iptables -C FORWARD -i eth0 -o "$WARP_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o "$WARP_IF" -j ACCEPT
iptables -C FORWARD -i "$WARP_IF" -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WARP_IF" -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -s "$WARP_SUBNET" -o "$WARP_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$WARP_SUBNET" -o "$WARP_IF" -j MASQUERADE

if [ "$WARP_IPV6_ENABLED" = "1" ]; then
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    ip -6 route replace "$WARP_SUBNET6" dev eth0 table 51822 || echo "IPv6 transit route unavailable; IPv6 client traffic will fail closed"
    ip -6 route replace default dev "$WARP_IF" table 51822 || echo "WARP IPv6 route unavailable; IPv6 client traffic will fail closed"
    while ip -6 rule del priority 210 from "$WARP_SUBNET6" table 51822 2>/dev/null; do :; done
    ip -6 rule add priority 210 from "$WARP_SUBNET6" table 51822 || true
    ip6tables -C FORWARD -i eth0 -o "$WARP_IF" -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i eth0 -o "$WARP_IF" -j ACCEPT || true
    ip6tables -C FORWARD -i "$WARP_IF" -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$WARP_IF" -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    ip6tables -t nat -C POSTROUTING -s "$WARP_SUBNET6" -o "$WARP_IF" -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -s "$WARP_SUBNET6" -o "$WARP_IF" -j MASQUERADE || true
fi

echo "Cloudflare WARP gateway ready on $WARP_IF"
tail -f /dev/null

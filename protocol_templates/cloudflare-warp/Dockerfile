FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ARG CLOUDFLARE_WARP_REPO_CODENAME=bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg dbus iproute2 iptables procps \
    && mkdir -p /usr/share/keyrings \
    && curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${CLOUDFLARE_WARP_REPO_CODENAME} main" > /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends cloudflare-warp \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/amnezia-warp-entrypoint
RUN chmod 0755 /usr/local/bin/amnezia-warp-entrypoint
ENTRYPOINT ["/usr/local/bin/amnezia-warp-entrypoint"]

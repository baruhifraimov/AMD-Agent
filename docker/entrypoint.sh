#!/bin/sh
set -e

# Block egress to private/local address space (requires NET_ADMIN)
if command -v iptables >/dev/null 2>&1; then
  iptables -A OUTPUT -d 127.0.0.0/8 -j DROP 2>/dev/null || true
  iptables -A OUTPUT -d 10.0.0.0/8 -j DROP 2>/dev/null || true
  iptables -A OUTPUT -d 172.16.0.0/12 -j DROP 2>/dev/null || true
  iptables -A OUTPUT -d 192.168.0.0/16 -j DROP 2>/dev/null || true
fi

mkdir -p /tmp/sandbox /data/models /data/benign
chmod 700 /tmp/sandbox

exec "$@"

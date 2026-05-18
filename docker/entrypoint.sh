#!/bin/sh
set -e

# Block egress to private/local address space (requires NET_ADMIN)
if command -v iptables >/dev/null 2>&1; then
  # Docker's embedded DNS commonly lives at 127.0.0.11; keep DNS usable.
  iptables -I OUTPUT 1 -p udp -d 127.0.0.11 --dport 53 -j ACCEPT 2>/dev/null || true
  iptables -I OUTPUT 1 -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT 2>/dev/null || true

  # Allow the configured Ollama endpoint before dropping private ranges.
  if [ -n "${AMD_OLLAMA_BASE_URL:-}" ]; then
    OLLAMA_HOST="$(printf '%s' "$AMD_OLLAMA_BASE_URL" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
    OLLAMA_PORT="$(printf '%s' "$AMD_OLLAMA_BASE_URL" | sed -nE 's#^[a-zA-Z]+://[^/:]+:([0-9]+).*#\1#p')"
    OLLAMA_PORT="${OLLAMA_PORT:-11434}"
    OLLAMA_IP="$(getent hosts "$OLLAMA_HOST" 2>/dev/null | awk '{print $1; exit}')"
    if [ -n "$OLLAMA_IP" ]; then
      iptables -I OUTPUT 1 -p tcp -d "$OLLAMA_IP" --dport "$OLLAMA_PORT" -j ACCEPT 2>/dev/null || true
    fi
  fi
  iptables -A OUTPUT -d 127.0.0.0/8 -j DROP 2>/dev/null || true
  iptables -A OUTPUT -d 10.0.0.0/8 -j DROP 2>/dev/null || true
  iptables -A OUTPUT -d 172.16.0.0/12 -j DROP 2>/dev/null || true
  iptables -A OUTPUT -d 192.168.0.0/16 -j DROP 2>/dev/null || true
fi

mkdir -p /tmp/sandbox /data/models /data/benign
chmod 700 /tmp/sandbox

exec "$@"

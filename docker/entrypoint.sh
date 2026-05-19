#!/bin/sh
set -e

add_accept() {
  iptables -C OUTPUT "$@" -j ACCEPT 2>/dev/null || iptables -I OUTPUT "$@" -j ACCEPT 2>/dev/null || true
}

add_drop() {
  iptables -C OUTPUT "$@" -j DROP 2>/dev/null || iptables -A OUTPUT "$@" -j DROP 2>/dev/null || true
}

add6_drop() {
  ip6tables -C OUTPUT "$@" -j DROP 2>/dev/null || ip6tables -A OUTPUT "$@" -j DROP 2>/dev/null || true
}

allow_dns_nameservers() {
  awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null | while read -r ns; do
    case "$ns" in
      *:*) continue ;;
      "")
        continue
        ;;
      *)
        add_accept -p udp -d "$ns" --dport 53
        add_accept -p tcp -d "$ns" --dport 53
        ;;
    esac
  done
}

allow_ollama_endpoint() {
  if [ -z "${AMD_OLLAMA_BASE_URL:-}" ]; then
    return
  fi

  ollama_host="$(printf '%s' "$AMD_OLLAMA_BASE_URL" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
  ollama_port="$(printf '%s' "$AMD_OLLAMA_BASE_URL" | sed -nE 's#^[a-zA-Z]+://[^/:]+:([0-9]+).*#\1#p')"
  ollama_port="${ollama_port:-11434}"

  getent ahostsv4 "$ollama_host" 2>/dev/null | awk '{print $1}' | sort -u | while read -r ip; do
    [ -n "$ip" ] || continue
    add_accept -p tcp -d "$ip" --dport "$ollama_port"
  done
}

# Block egress to private/local address space while preserving:
# - Docker DNS only on port 53
# - configured Ollama endpoint only on its TCP port
if command -v iptables >/dev/null 2>&1; then
  allow_dns_nameservers
  allow_ollama_endpoint

  add_drop -d 127.0.0.0/8
  add_drop -d 10.0.0.0/8
  add_drop -d 172.16.0.0/12
  add_drop -d 192.168.0.0/16
  add_drop -d 169.254.0.0/16
fi

if command -v ip6tables >/dev/null 2>&1; then
  add6_drop -d ::1/128
  add6_drop -d fc00::/7
  add6_drop -d fe80::/10
fi

mkdir -p /tmp/sandbox /data/models /data/benign
chmod 700 /tmp/sandbox

exec "$@"

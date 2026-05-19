#!/bin/sh
set -e

log() {
  printf '%s\n' "amd-net-guard: $*" >&2
}

add_accept() {
  iptables -C OUTPUT "$@" -j ACCEPT 2>/dev/null && return
  iptables -I OUTPUT "$@" -j ACCEPT 2>/dev/null && return
  log "warning: failed to add IPv4 ACCEPT rule: $*"
}

add6_accept() {
  ip6tables -C OUTPUT "$@" -j ACCEPT 2>/dev/null && return
  ip6tables -I OUTPUT "$@" -j ACCEPT 2>/dev/null && return
  log "warning: failed to add IPv6 ACCEPT rule: $*"
}

add_drop() {
  iptables -C OUTPUT "$@" -j DROP 2>/dev/null && return
  iptables -A OUTPUT "$@" -j DROP 2>/dev/null && return
  log "warning: failed to add IPv4 DROP rule: $*"
}

add6_drop() {
  ip6tables -C OUTPUT "$@" -j DROP 2>/dev/null && return
  ip6tables -A OUTPUT "$@" -j DROP 2>/dev/null && return
  log "warning: failed to add IPv6 DROP rule: $*"
}

allow_dns_target() {
  target="$1"
  [ -n "$target" ] || return

  case "$target" in
    127.0.0.11)
      # Docker's embedded DNS is advertised as 127.0.0.11:53, but Docker may
      # DNAT it to an internal high port before filter/OUTPUT rules see it.
      log "allow Docker embedded DNS IPv4 $target"
      add_accept -p udp -d "$target"
      add_accept -p tcp -d "$target"
      ;;
    *:*)
      if command -v ip6tables >/dev/null 2>&1; then
        log "allow DNS IPv6 $target:53"
        add6_accept -p udp -d "$target" --dport 53
        add6_accept -p tcp -d "$target" --dport 53
      fi
      ;;
    *)
      log "allow DNS IPv4 $target:53"
      add_accept -p udp -d "$target" --dport 53
      add_accept -p tcp -d "$target" --dport 53
      ;;
  esac
}

allow_docker_dns_upstream_target() {
  target="$1"
  [ -n "$target" ] || return

  case "$target" in
    *:*)
      if command -v ip6tables >/dev/null 2>&1; then
        log "allow Docker DNS upstream IPv6 $target"
        add6_accept -p udp -d "$target"
        add6_accept -p tcp -d "$target"
      fi
      ;;
    *)
      # Docker Desktop can DNAT embedded DNS traffic to the upstream resolver
      # before filter/OUTPUT sees it, so the visible destination port may not
      # remain 53. Limit this exception to the resolver IP only.
      log "allow Docker DNS upstream IPv4 $target"
      add_accept -p udp -d "$target"
      add_accept -p tcp -d "$target"
      ;;
  esac
}

allow_dns_nameservers() {
  awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null | while read -r ns; do
    allow_dns_target "$ns"
  done

  # Docker Desktop may proxy DNS through a host-side resolver listed only in a
  # resolv.conf comment, for example: ExtServers: [host(192.168.65.7)].
  sed -n 's/^# ExtServers: \[\(.*\)\]/\1/p' /etc/resolv.conf 2>/dev/null \
    | tr ',' '\n' \
    | sed -n 's/.*(\([^)]*\)).*/\1/p' \
    | while read -r ns; do
      allow_docker_dns_upstream_target "$ns"
    done
}

allow_ollama_target() {
  target="$1"
  port="$2"
  [ -n "$target" ] || return

  case "$target" in
    *:*)
      if command -v ip6tables >/dev/null 2>&1; then
        log "allow Ollama IPv6 [$target]:$port"
        add6_accept -p tcp -d "$target" --dport "$port"
      fi
      ;;
    *)
      log "allow Ollama IPv4 $target:$port"
      add_accept -p tcp -d "$target" --dport "$port"
      ;;
  esac
}

resolve_host_targets() {
  host="$1"

  if printf '%s' "$host" | grep -Eq '^([0-9.]+|[0-9a-fA-F:]+)$'; then
    printf '%s\n' "$host"
  fi

  getent ahosts "$host" 2>/dev/null | awk '{print $1}'
  getent hosts "$host" 2>/dev/null | awk '{print $1}'
}

parse_url_host_port() {
  url="$1"
  default_port="$2"
  endpoint="${url#*://}"
  endpoint="${endpoint%%/*}"

  case "$endpoint" in
    \[*\]*)
      parsed_host="${endpoint#\[}"
      parsed_host="${parsed_host%%\]*}"
      parsed_port="${endpoint#*\]}"
      parsed_port="${parsed_port#:}"
      ;;
    *:*)
      parsed_host="${endpoint%%:*}"
      parsed_port="${endpoint##*:}"
      ;;
    *)
      parsed_host="$endpoint"
      parsed_port="$default_port"
      ;;
  esac

  [ -n "$parsed_port" ] || parsed_port="$default_port"
  printf '%s %s\n' "$parsed_host" "$parsed_port"
}

allow_ollama_endpoint() {
  if [ -z "${AMD_OLLAMA_BASE_URL:-}" ]; then
    return
  fi

  set -- $(parse_url_host_port "$AMD_OLLAMA_BASE_URL" "11434")
  ollama_host="$1"
  ollama_port="$2"

  resolve_host_targets "$ollama_host" | sort -u | while read -r ip; do
    allow_ollama_target "$ip" "$ollama_port"
  done
}

# Block egress to private/local address space while preserving:
# - Docker DNS only on port 53
# - configured Ollama endpoint only on its TCP port
if command -v iptables >/dev/null 2>&1; then
  log "applying egress guard"
  add_accept -o lo
  allow_dns_nameservers
  allow_ollama_endpoint

  add_drop -d 127.0.0.0/8
  add_drop -d 10.0.0.0/8
  add_drop -d 172.16.0.0/12
  add_drop -d 192.168.0.0/16
  add_drop -d 169.254.0.0/16
  log "IPv4 private/local egress blocked"
fi

if command -v ip6tables >/dev/null 2>&1; then
  add6_accept -o lo
  add6_drop -d ::1/128
  add6_drop -d fc00::/7
  add6_drop -d fe80::/10
  log "IPv6 local/private egress blocked"
fi

mkdir -p /tmp/sandbox /data/models /data/benign
chmod 700 /tmp/sandbox

exec "$@"

#!/bin/sh
set -eu

config_path="${THREATINGESTOR_CONFIG:-/app/threatingestor_config.yml}"

python -m src.threatingestor_bridge --daemon &
bridge_pid="$!"

threatingestor "$config_path" &
ingestor_pid="$!"

shutdown() {
  kill "$bridge_pid" "$ingestor_pid" 2>/dev/null || true
}

trap shutdown INT TERM EXIT
wait "$ingestor_pid"

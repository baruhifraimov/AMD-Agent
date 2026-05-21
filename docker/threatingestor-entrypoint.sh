#!/bin/sh
set -eu

template_config="${THREATINGESTOR_CONFIG:-/app/threatingestor_config.yml}"
runtime_config="${THREATINGESTOR_RUNTIME_CONFIG:-/data/threatingestor_config.runtime.yml}"

run_threatingestor_once() {
  if [ "${AMD_THREATINGESTOR_VERBOSE:-0}" = "1" ]; then
    threatingestor "$runtime_config" || true
    return 0
  fi

  before_file="$(mktemp)"
  log_file="$(mktemp)"
  status=0

  python -m src.intel.threatingestor_summary --snapshot "$before_file" || true

  if threatingestor "$runtime_config" >"$log_file" 2>&1; then
    status=0
  else
    status=$?
  fi

  python -m src.intel.threatingestor_summary \
    --before "$before_file" \
    --log "$log_file" \
    --exit-code "$status" || true

  if [ "$status" -ne 0 ]; then
    echo "ThreatIngestor raw log tail (failure):"
    tail -n 20 "$log_file" || true
  fi

  rm -f "$before_file" "$log_file"
}

while true; do
  python -m src.intel.threatingestor_sleep \
    --write-runtime-config \
    --template "$template_config" \
    --output "$runtime_config" >/dev/null

  AMD_COLLECTION_PHASE="$(python -c "from src.collection.context import current_collection_phase; print(current_collection_phase())")"
  export AMD_COLLECTION_PHASE

  if [ "$AMD_COLLECTION_PHASE" = "bootstrap" ]; then
    echo "ThreatIngestor skipped: AMD_COLLECTION_PHASE=bootstrap (awaiting 100/100 trainable samples)"
    interval="$(python -m src.intel.threatingestor_sleep)"
    sleep "$interval"
    continue
  fi

  run_threatingestor_once

  interval="$(python -m src.intel.threatingestor_sleep)"
  echo "ThreatIngestor sleeping ${interval}s before next pass (AMD_COLLECTION_PHASE=${AMD_COLLECTION_PHASE})"
  sleep "$interval"
done

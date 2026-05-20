#!/bin/sh
set -eu

template_config="${THREATINGESTOR_CONFIG:-/app/threatingestor_config.yml}"
runtime_config="${THREATINGESTOR_RUNTIME_CONFIG:-/data/threatingestor_config.runtime.yml}"

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

  threatingestor "$runtime_config" || true

  interval="$(python -m src.intel.threatingestor_sleep)"
  echo "ThreatIngestor sleeping ${interval}s before next pass (AMD_COLLECTION_PHASE=${AMD_COLLECTION_PHASE})"
  sleep "$interval"
done

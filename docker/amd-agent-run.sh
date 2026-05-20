#!/bin/sh
set -eu

log() {
  printf '%s\n' "amd-agent-run: $*" >&2
}

log "preflight"
python /app/scripts/preflight_check.py || log "preflight returned non-zero (continuing)"

if python -c "
from src.db.tracker import get_tracker
from src.ml.classifier import load_bundle, model_bundle_ready, training_targets_met
counts = get_tracker().count_by_label()
raise SystemExit(0 if training_targets_met(counts) and model_bundle_ready(load_bundle()) else 1)
"; then
  log "bootstrap skipped (trainable targets and model bundle ready)"
else
  log "running bootstrap"
  python -m src.graph --bootstrap
fi

log "starting daemon"
exec python -m src.graph --daemon

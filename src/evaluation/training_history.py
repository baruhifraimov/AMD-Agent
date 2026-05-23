"""Append-only retrain history with per-run accuracy delta vs previous run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import src.config as cfg

DELTA_METRIC_KEYS: tuple[str, ...] = ("accuracy", "precision", "recall", "tpr", "fpr")


def append_history(record: dict[str, Any], path: Path | None = None) -> None:
    """Append one retrain record to training_history.jsonl."""
    cfg.ensure_dirs()
    p = path or cfg.TRAINING_HISTORY_PATH
    with p.open("a") as f:
        f.write(json.dumps(record) + "\n")


def read_last_history(path: Path | None = None) -> dict[str, Any] | None:
    """Return the last record in training_history.jsonl, or None if missing/empty."""
    p = path or cfg.TRAINING_HISTORY_PATH
    if not p.exists():
        return None
    last: dict[str, Any] | None = None
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    return last


def count_retrains(path: Path | None = None) -> int:
    """Return number of retrain records on disk."""
    p = path or cfg.TRAINING_HISTORY_PATH
    if not p.exists():
        return 0
    count = 0
    with p.open() as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def compute_delta_pct(
    current: dict[str, float],
    previous: dict[str, float] | None,
    keys: tuple[str, ...] = DELTA_METRIC_KEYS,
) -> dict[str, float]:
    """Percent change per metric vs previous run. Baseline (no previous) returns zeros."""
    if not previous:
        return {k: 0.0 for k in keys if k in current}
    deltas: dict[str, float] = {}
    for k in keys:
        if k not in current or k not in previous:
            continue
        prev_val = float(previous[k])
        curr_val = float(current[k])
        if prev_val == 0.0:
            deltas[k] = 0.0
        else:
            deltas[k] = (curr_val - prev_val) / prev_val * 100.0
    return deltas

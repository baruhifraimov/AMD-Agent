"""Append-only concept drift evidence log for the final report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import src.config as cfg
from src.state import AgentState

REPORT_EXCERPT_MAX = 200


def append_drift_log(record: dict[str, Any], path: Path | None = None) -> None:
    """Append one drift event record to drift_log.jsonl."""
    cfg.ensure_dirs()
    p = path or cfg.DRIFT_LOG_PATH
    with p.open("a") as f:
        f.write(json.dumps(record) + "\n")


def build_drift_record(
    state: AgentState,
    *,
    post_metrics: dict[str, float],
) -> dict[str, Any]:
    """Build a JSON-serializable drift event from graph state and post-retrain metrics."""
    excerpt = ""
    if state.semantic_report:
        excerpt = state.semantic_report[:REPORT_EXCERPT_MAX]

    new_batch_size = float(
        state.evaluation_metrics.get(
            "new_batch_size",
            float(len(state.new_labeled_batch)),
        )
    )
    retrained = state.evaluation_metrics.get("retrained")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "concept_drift",
        "drift_stats": dict(state.drift_stats),
        "new_batch_size": new_batch_size,
        "retrained": retrained,
        "pre_metrics": dict(state.drift_pre_metrics),
        "post_metrics": dict(post_metrics),
        "semantic_report_excerpt": excerpt,
    }

"""Tests for drift_log.jsonl reporting."""

import json

from src.evaluation.drift_log import append_drift_log, build_drift_record
from src.state import AgentState


def test_append_drift_log_writes_jsonl(tmp_paths):
    path = tmp_paths["db"].parent / "drift_log.jsonl"
    record = {"timestamp": "2024-01-01T00:00:00+00:00", "event": "concept_drift"}
    append_drift_log(record, path=path)
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "concept_drift"


def test_build_drift_record_includes_pre_post_and_excerpt():
    state = AgentState(
        drift_stats={"mean_shift": 1.5},
        drift_pre_metrics={"accuracy": 0.9, "fpr": 0.01},
        evaluation_metrics={"retrained": 1.0, "new_batch_size": 2.0},
        semantic_report="Drift detected. " + ("x" * 300),
        new_labeled_batch=[{"sha256": "a" * 64}],
    )
    record = build_drift_record(state, post_metrics={"accuracy": 0.95, "fpr": 0.005})
    assert record["event"] == "concept_drift"
    assert record["pre_metrics"]["accuracy"] == 0.9
    assert record["post_metrics"]["accuracy"] == 0.95
    assert record["retrained"] == 1.0
    assert len(record["semantic_report_excerpt"]) <= 200

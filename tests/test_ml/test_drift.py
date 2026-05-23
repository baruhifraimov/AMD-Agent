"""ADWIN drift detection, drift monitor node, and drift log."""

import json
from unittest.mock import MagicMock, patch

from src.evaluation.drift_log import append_drift_log, build_drift_record
from src.ml.drift import DriftMonitor
from src.ml.services.drift_monitor import DriftMonitorService
from src.nodes.drift_monitor import drift_monitor
from src.state import AgentState


def test_adwin_detects_shift(tmp_paths):
    monitor = DriftMonitor()
    monitor.reset_detector()
    drift = False
    for _ in range(50):
        monitor.update(0.1)
    for _ in range(50):
        if monitor.update(5.0):
            drift = True
            break
    assert drift


@patch("src.ml.drift.ADWIN_DELTA", 0.03)
def test_new_detector_uses_config_delta(tmp_paths):
    monitor = DriftMonitor()
    monitor.reset_detector()
    assert monitor.detector.delta == 0.03


def test_drift_labels_only_triggered_samples():
    monitor = MagicMock()
    monitor.update.side_effect = [False, True, True]
    resolver = MagicMock()
    resolver.resolve_label.side_effect = [1, None]
    service = DriftMonitorService(monitor=monitor, resolver=resolver)
    drift, batch, _stats = service.update_batch(
        [
            {"sha256": "a" * 64, "avg_section_entropy": 0.5},
            {"sha256": "b" * 64, "avg_section_entropy": 0.6},
            {"sha256": "c" * 64, "avg_section_entropy": 0.7},
        ],
        [0.5, 0.6, 0.7],
        hash_metadata={},
    )
    assert drift is True
    assert len(batch) == 1 and batch[0]["sha256"] == "b" * 64


@patch("src.nodes.drift_monitor.build_collection_context")
@patch("src.nodes.drift_monitor.DriftMonitorService")
def test_drift_node_skips_bootstrap(mock_service, mock_ctx, tmp_paths):
    from src.collection.context import CollectionContext

    mock_ctx.return_value = CollectionContext(
        benign_count=50, malware_count=50, model_ready=False, pending_depth=0
    )
    out = drift_monitor(
        AgentState(
            collection_phase="bootstrap",
            feature_vectors=[{"sha256": "e" * 64}],
            section_entropies=[7.0],
        )
    )
    assert out["drift_detected"] is False
    mock_service.assert_not_called()


@patch("src.evaluation.tesseract.latest_eval_metrics", return_value={"accuracy": 0.9})
@patch("src.nodes.drift_monitor.DriftMonitorService")
def test_drift_node_sets_pending_log_on_drift(mock_service, mock_eval, tmp_paths):
    mock_service.return_value.update_batch.return_value = (
        True,
        [{"sha256": "a" * 64, "label": 1}],
        {"mean_shift": 1.6},
    )
    with patch("src.nodes.drift_monitor.build_collection_context") as mock_ctx:
        from src.collection.context import CollectionContext

        mock_ctx.return_value = CollectionContext(
            benign_count=100, malware_count=100, model_ready=True, pending_depth=0
        )
        out = drift_monitor(
            AgentState(
                collection_phase="steady",
                feature_vectors=[{"sha256": "a" * 64}],
                section_entropies=[0.5],
            )
        )
    assert out["pending_drift_log"] is True
    assert out["drift_pre_metrics"]["accuracy"] == 0.9


def test_drift_log_record_and_append(tmp_paths):
    path = tmp_paths["db"].parent / "drift_log.jsonl"
    append_drift_log({"timestamp": "2024-01-01T00:00:00+00:00", "event": "concept_drift"}, path=path)
    assert json.loads(path.read_text().strip())["event"] == "concept_drift"
    record = build_drift_record(
        AgentState(
            drift_stats={"mean_shift": 1.5},
            drift_pre_metrics={"accuracy": 0.9},
            evaluation_metrics={"retrained": 1.0},
            semantic_report="x" * 300,
        ),
        post_metrics={"accuracy": 0.95},
    )
    assert record["event"] == "concept_drift"
    assert len(record["semantic_report_excerpt"]) <= 200

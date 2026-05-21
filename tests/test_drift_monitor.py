"""Tests for drift monitor verified per-sample labeling."""

from unittest.mock import MagicMock, patch

from src.ml.services.drift_monitor import DriftMonitorService
from src.nodes.drift_monitor import drift_monitor
from src.state import AgentState


def test_drift_labels_only_triggered_samples():
    monitor = MagicMock()
    monitor.update.side_effect = [False, True, True]
    resolver = MagicMock()
    resolver.resolve_label.side_effect = [1, None]
    service = DriftMonitorService(monitor=monitor, resolver=resolver)
    sha_a, sha_b, sha_c = "a" * 64, "b" * 64, "c" * 64
    drift, batch, stats = service.update_batch(
        [
            {"sha256": sha_a, "avg_section_entropy": 0.5},
            {"sha256": sha_b, "avg_section_entropy": 0.6},
            {"sha256": sha_c, "avg_section_entropy": 0.7},
        ],
        [0.5, 0.6, 0.7],
        hash_metadata={},
    )
    assert drift is True
    assert len(batch) == 1
    assert batch[0]["sha256"] == sha_b
    assert batch[0]["label"] == 1
    assert resolver.resolve_label.call_count == 2
    assert isinstance(stats, dict)


@patch("src.nodes.drift_monitor.build_collection_context")
@patch("src.nodes.drift_monitor.DriftMonitorService")
def test_drift_node_delegates_to_service(mock_service, mock_ctx, tmp_paths):
    from src.collection.context import CollectionContext

    mock_ctx.return_value = CollectionContext(
        benign_count=100, malware_count=100, model_ready=True, pending_depth=0
    )
    mock_service.return_value.update_batch.return_value = (False, [], {})
    state = AgentState(
        feature_vectors=[{"sha256": "e" * 64}],
        section_entropies=[0.5],
        expected_label=0,
    )
    out = drift_monitor(state)
    assert "drift_detected" in out
    assert "new_labeled_batch" in out


@patch("src.nodes.drift_monitor.build_collection_context")
@patch("src.nodes.drift_monitor.DriftMonitorService")
def test_drift_node_skips_during_bootstrap(mock_service, mock_ctx, tmp_paths):
    from src.collection.context import CollectionContext

    mock_ctx.return_value = CollectionContext(
        benign_count=50, malware_count=50, model_ready=False, pending_depth=0
    )
    state = AgentState(
        collection_phase="bootstrap",
        feature_vectors=[{"sha256": "e" * 64, "avg_section_entropy": 7.0}],
        section_entropies=[7.0],
        expected_label=0,
    )
    out = drift_monitor(state)
    assert out["drift_detected"] is False
    assert out["new_labeled_batch"] == []
    assert out["pending_drift_log"] is False
    mock_service.assert_not_called()


@patch("src.evaluation.tesseract.latest_eval_metrics", return_value={"accuracy": 0.9})
@patch("src.nodes.drift_monitor.DriftMonitorService")
def test_drift_node_sets_pending_log_on_drift(mock_service, mock_eval, tmp_paths):
    mock_svc = mock_service.return_value
    mock_svc.update_batch.return_value = (
        True,
        [{"sha256": "a" * 64, "label": 1}],
        {"mean_shift": 1.6, "corr_shift": 0.4},
    )
    state = AgentState(
        collection_phase="steady",
        feature_vectors=[{"sha256": "a" * 64}],
        section_entropies=[0.5],
    )
    with patch("src.nodes.drift_monitor.build_collection_context") as mock_ctx:
        from src.collection.context import CollectionContext

        mock_ctx.return_value = CollectionContext(
            benign_count=100, malware_count=100, model_ready=True, pending_depth=0
        )
        out = drift_monitor(state)
    assert out["drift_detected"] is True
    assert out["pending_drift_log"] is True
    assert out["drift_pre_metrics"] == {"accuracy": 0.9}
    assert out["drift_stats"]["mean_shift"] == 1.6
    mock_eval.assert_called_once()

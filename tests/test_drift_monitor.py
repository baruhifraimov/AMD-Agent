"""Tests for drift monitor verified per-sample labeling."""

from unittest.mock import MagicMock

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
    drift, batch = service.update_batch(
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


def test_drift_node_delegates_to_service():
    state = AgentState(
        feature_vectors=[{"sha256": "e" * 64}],
        section_entropies=[0.5],
        expected_label=0,
    )
    out = drift_monitor(state)
    assert "drift_detected" in out
    assert "new_labeled_batch" in out

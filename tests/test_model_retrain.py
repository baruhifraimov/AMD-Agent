"""Tests for model_retrain node MADAR wiring."""

from unittest.mock import patch

from src.nodes.model_retrain import model_retrain
from src.state import AgentState


@patch("src.nodes.model_retrain.madar_retrain")
@patch("src.nodes.model_retrain.ingest_benign_corpus")
def test_model_retrain_calls_madar_retrain(mock_ingest, mock_madar, tmp_paths):
    mock_madar.return_value = {"threshold": 0.42, "model": "m"}
    sha = "f" * 64
    state = AgentState(
        new_labeled_batch=[{"sha256": sha, "label": 1, "avg_section_entropy": 1.0}],
    )
    out = model_retrain(state)
    mock_madar.assert_called_once()
    assert out["evaluation_metrics"]["retrained"] == 1.0


@patch("src.nodes.model_retrain.madar_retrain")
def test_model_retrain_skips_unlabeled_drift_batch(mock_madar):
    state = AgentState(new_labeled_batch=[{"sha256": "a" * 64}])
    out = model_retrain(state)
    mock_madar.assert_not_called()
    assert out["evaluation_metrics"]["retrained"] == 0.0

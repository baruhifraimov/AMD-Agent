import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from src.evaluation.tesseract import run_retrograde_eval

@patch("src.evaluation.tesseract.load_bundle")
@patch("src.evaluation.tesseract.score_feature_matrix")
@patch("src.db.tracker.get_tracker")
def test_retrograde_eval(mock_get_tracker, mock_score, mock_load):
    mock_tracker = MagicMock()
    mock_get_tracker.return_value = mock_tracker
    
    mock_tracker.get_all_task_ids.return_value = [1, 2]
    
    mock_tracker.fetch_task_holdout.side_effect = [
        [
            {"features": {"avg_section_entropy": 0.5}, "label": 1},
            {"features": {"avg_section_entropy": 0.2}, "label": 0},
        ],
        [
            {"features": {"avg_section_entropy": 0.9}, "label": 1},
        ],
    ]
    
    mock_load.return_value = {
        "model": MagicMock(),
        "threshold": 0.5,
        "feature_dim": 2304,
        "feature_set_version": "ember_static_v1",
        "feature_names": ["f1"] * 2304,
    }
    
    # 3 samples total, predict them
    mock_score.side_effect = [
        np.array([0.9, 0.1]),  # Task 1: TP, TN -> 1.0 acc
        np.array([0.2]),       # Task 2: FN -> 0.0 acc
    ]
    
    metrics = run_retrograde_eval(mock_tracker)
    
    assert "task_1_accuracy" in metrics
    assert metrics["task_1_accuracy"] == 1.0
    assert "task_2_accuracy" in metrics
    assert metrics["task_2_accuracy"] == 0.0
    
    assert "retrograde_accuracy" in metrics
    assert round(metrics["retrograde_accuracy"], 2) == 0.67  # (2.0) / 3

"""Tests for TESSERACT AUT and plotting outputs."""

from unittest.mock import patch

import numpy as np

from src.config import FEATURE_NAMES
from src.evaluation.tesseract import append_eval_log, plot_performance_decay, run_tesseract_eval


def _features(value: float) -> dict[str, float]:
    return {name: value for name in FEATURE_NAMES}


@patch("src.evaluation.tesseract.compute_aut", return_value=0.75)
@patch("src.evaluation.tesseract.fit_threshold", return_value=0.5)
@patch("src.evaluation.tesseract.predict_proba")
@patch("src.evaluation.tesseract.load_bundle", return_value={"model": object()})
def test_run_tesseract_eval_writes_aut_metric(
    mock_bundle,
    mock_predict,
    mock_threshold,
    mock_aut,
    tmp_paths,
):
    tracker = tmp_paths["tracker"]
    for i in range(10):
        sha = f"{i:064x}"
        tracker.insert_sample(
            sha,
            f"/tmp/{sha}.bin",
            f"2024-01-{i + 1:02d} 00:00:00",
            features=_features(float(i)),
            label=0 if i < 5 else 1,
        )
    mock_predict.side_effect = lambda model, X: np.linspace(0.0, 1.0, len(X))

    metrics = run_tesseract_eval(tracker)

    assert metrics["aut"] == 0.75
    mock_aut.assert_called_once()


def test_plot_performance_decay_uses_figures_dir(tmp_paths):
    append_eval_log({"accuracy": 0.9, "fpr": 0.01})
    out_path = plot_performance_decay()
    assert out_path == tmp_paths["figures"] / "performance_decay.png"
    assert out_path.exists()

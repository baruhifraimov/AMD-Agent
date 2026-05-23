"""Tests for TESSERACT AUT and plotting outputs."""

from unittest.mock import patch

import numpy as np

from src.config import FEATURE_DIM, FEATURE_NAMES, FEATURE_SET_VERSION
from src.evaluation.tesseract import append_eval_log, plot_performance_decay, run_tesseract_eval


def _features(value: float) -> dict[str, float]:
    return {name: value for name in FEATURE_NAMES}


@patch("src.evaluation.tesseract.compute_aut", return_value=0.75)
@patch("src.evaluation.tesseract.score_feature_matrix")
@patch("src.evaluation.tesseract.fit_model_artifact")
@patch(
    "src.evaluation.tesseract.load_bundle",
    return_value={
        "model": object(),
        "training_counts": {"0": 100, "1": 100},
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_dim": FEATURE_DIM,
        "feature_names": FEATURE_NAMES,
    },
)
def test_run_tesseract_eval_writes_aut_metric(
    mock_bundle,
    mock_fit,
    mock_score,
    mock_aut,
    tmp_paths,
):
    tracker = tmp_paths["tracker"]
    for i in range(20):
        sha = f"{i:064x}"
        tracker.insert_sample(
            sha,
            f"/tmp/{sha}.bin",
            f"2024-01-{i + 1:02d} 00:00:00",
            features=_features(float(i)),
            label=i % 2,
        )
    mock_fit.return_value = {"model": object(), "threshold": 0.5}
    mock_score.side_effect = lambda bundle, X: np.linspace(0.0, 1.0, len(X))

    metrics = run_tesseract_eval(tracker)

    assert metrics["aut"] == 0.75
    mock_aut.assert_called_once()


@patch("src.evaluation.tesseract.fit_model_artifact")
@patch(
    "src.evaluation.tesseract.load_bundle",
    return_value={
        "model": object(),
        "training_counts": {"0": 100, "1": 100},
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_dim": FEATURE_DIM,
        "feature_names": FEATURE_NAMES,
    },
)
def test_run_tesseract_eval_skips_single_class_temporal_tail(
    mock_bundle,
    mock_fit,
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

    assert run_tesseract_eval(tracker) == {}
    mock_fit.assert_not_called()


def test_training_order_uses_ingested_at_not_source_first_seen(tmp_paths):
    tracker = tmp_paths["tracker"]
    benign_sha = "b" * 64
    malware_sha = "c" * 64
    tracker.insert_sample(
        malware_sha,
        f"/tmp/{malware_sha}.bin",
        "2020-01-01 00:00:00",
        features=_features(1.0),
        label=1,
        ingested_at="2024-01-02 00:00:00",
        source_first_seen="2020-01-01 00:00:00",
    )
    tracker.insert_sample(
        benign_sha,
        f"/tmp/{benign_sha}.bin",
        "2024-01-01 00:00:00",
        features=_features(0.0),
        label=0,
        ingested_at="2024-01-01 00:00:00",
    )

    rows = tracker.fetch_labeled_with_features()
    assert [row["sha256"] for row in rows] == [benign_sha, malware_sha]


def test_plot_performance_decay_uses_figures_dir(tmp_paths):
    append_eval_log({"accuracy": 0.9, "fpr": 0.01})
    out_path = plot_performance_decay()
    assert out_path == tmp_paths["figures"] / "performance_decay.png"
    assert out_path.exists()

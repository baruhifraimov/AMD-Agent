"""Tests for classifier threshold and training."""

from unittest.mock import patch

import numpy as np

from src.config import FEATURE_NAMES
from src.ml.classifier import cold_start_train, fit_threshold, retrain_model


def test_fit_threshold_low_fpr():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    thr = fit_threshold(y, scores, target_fpr=0.25)
    assert 0.0 <= thr <= 1.0


@patch("src.ml.classifier.lgb.LGBMClassifier")
@patch("src.ml.classifier.load_bundle", return_value={"model": "existing", "threshold": 0.7})
def test_retrain_model_reuses_bundle_for_single_class(mock_load_bundle, mock_lgb):
    X = np.ones((8, len(FEATURE_NAMES)))
    y = np.ones(8, dtype=int)

    bundle = retrain_model(X, y)

    assert bundle == {"model": "existing", "threshold": 0.7}
    mock_load_bundle.assert_called_once()
    mock_lgb.assert_not_called()


@patch("src.ml.classifier.lgb.LGBMClassifier")
def test_cold_start_skips_single_class_chronological_train(mock_lgb, tmp_paths):
    tracker = tmp_paths["tracker"]
    for i in range(20):
        sha = f"{i:064x}"
        tracker.insert_sample(
            sha,
            f"/tmp/{sha}.bin",
            f"2024-01-{i + 1:02d} 00:00:00",
            features={name: float(i) for name in FEATURE_NAMES},
            label=0 if i < 15 else 1,
        )

    assert cold_start_train(tracker) is None
    mock_lgb.assert_not_called()

"""Tests for classifier threshold and training."""

import warnings
from unittest.mock import patch

import numpy as np

from src.config import FEATURE_NAMES
from src.ml.classifier import (
    _adaptive_min_data_in_leaf,
    _lgbm_default_params,
    cold_start_train,
    fit_model_artifact,
    fit_threshold,
    model_bundle_ready,
    predict_proba,
    retrain_model,
)
from src.ml.splits import temporal_split


def test_fit_threshold_low_fpr():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    thr = fit_threshold(y, scores, target_fpr=0.25)
    assert 0.0 <= thr <= 1.0


def test_old_feature_bundle_not_ready():
    bundle = {
        "model": object(),
        "threshold": 0.5,
        "training_counts": {"0": 100, "1": 100},
        "feature_names": [f"old_{i}" for i in range(17)],
    }
    assert model_bundle_ready(bundle) is False


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


def test_temporal_split_preserves_order():
    X = np.arange(20).reshape(20, 1).astype(float)
    y = np.arange(20, dtype=int)
    X_train, y_train, X_val, y_val, X_test, y_test = temporal_split(
        X, y, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15
    )
    assert len(y_train) == 14
    assert len(y_val) == 3
    assert len(y_test) == 3
    assert y_train[-1] == 13
    assert y_val[0] == 14
    assert y_test[0] == 17


def test_adaptive_min_data_in_leaf_scales_with_train_size():
    assert _adaptive_min_data_in_leaf(40) == 5
    assert _adaptive_min_data_in_leaf(200) == 10
    params = _lgbm_default_params(200)
    assert params["min_data_in_leaf"] == 10
    assert params["class_weight"] == "balanced"


def test_fit_model_artifact_records_temporal_split_metadata():
    rng = np.random.default_rng(0)
    n = 40
    X = rng.random((n, len(FEATURE_NAMES)))
    y = np.array([0] * 20 + [1] * 20, dtype=int)
    X_train, y_train, X_val, y_val, _, _ = temporal_split(X, y, train_ratio=0.7, val_ratio=0.15)
    bundle = fit_model_artifact(
        X_train,
        y_train,
        X_val,
        y_val,
        optimize=False,
        split_mode="temporal",
    )
    meta = bundle["split_metadata"]
    assert meta["split_mode"] == "temporal"
    assert meta["train_class_counts"][0] + meta["train_class_counts"][1] == len(y_train)


def test_predict_proba_uses_named_features_without_sklearn_warning():
    import lightgbm as lgb

    n = 12
    X = np.random.default_rng(42).random((n, len(FEATURE_NAMES)))
    y = np.array([0] * 6 + [1] * 6, dtype=int)
    model = lgb.LGBMClassifier(n_estimators=5, verbose=-1)
    from src.ml.classifier import _feature_frame

    model.fit(_feature_frame(X), y)
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "error",
            message=".*does not have valid feature names.*",
            category=UserWarning,
        )
        scores = predict_proba(model, X)
    assert scores.shape == (n,)

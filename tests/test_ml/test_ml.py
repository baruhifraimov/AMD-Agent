"""ML classifier, MADAR replay, retrain, and dynamic FPR."""

import warnings
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from src.config import (
    FEATURE_DIM,
    FEATURE_NAMES,
    FEATURE_SET_VERSION,
    TARGET_FPR,
    TARGET_FPR_BOOTSTRAP,
    TARGET_FPR_GROWTH,
    get_dynamic_target_fpr,
)
from src.ml.classifier import (
    cold_start_train,
    continue_training,
    fit_model_artifact,
    fit_threshold,
    model_bundle_ready,
    predict_proba,
    retrain_model,
    resolve_target_fpr,
)
from src.ml.madar import build_madar_replay, madar_retrain
from src.ml.replay_budget import RatioBudget, UniformBudget
from src.ml.splits import temporal_split
from src.ml.services.retrain import RetrainService
from src.nodes.model_retrain import model_retrain
from src.evaluation.tesseract import run_retrograde_eval
from src.state import AgentState


def test_agent_state_accepts_string_evaluation_metrics():
    """Regression: graph merge after model_retrain must not reject string metadata."""
    state = AgentState()
    updates = {
        "evaluation_metrics": {
            "retrained": 1.0,
            "retrain_trigger": "threshold_retrain",
            "model_version": "v_20260523_173626",
        }
    }
    merged = AgentState.model_validate({**state.model_dump(), **updates})
    assert merged.evaluation_metrics["retrain_trigger"] == "threshold_retrain"


def test_fit_threshold_low_fpr():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    assert 0.0 <= fit_threshold(y, scores, target_fpr=0.25) <= 1.0


def test_model_bundle_ready_rejects_stale_features():
    bundle = {
        "model": object(),
        "threshold": 0.5,
        "training_counts": {"0": 100, "1": 100},
        "feature_names": [f"old_{i}" for i in range(17)],
    }
    assert model_bundle_ready(bundle) is False


def test_temporal_split_preserves_order():
    X = np.arange(20).reshape(20, 1).astype(float)
    y = np.arange(20, dtype=int)
    X_train, y_train, X_val, y_val, X_test, y_test = temporal_split(
        X, y, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15
    )
    assert len(y_train) == 14 and y_train[-1] == 13
    assert y_val[0] == 14 and y_test[0] == 17


@pytest.mark.parametrize(
    "benign_count,expected",
    [
        (0, TARGET_FPR_BOOTSTRAP),
        (1000, TARGET_FPR_GROWTH),
        (5000, TARGET_FPR),
    ],
)
def test_dynamic_target_fpr_tiers(benign_count, expected):
    assert get_dynamic_target_fpr(benign_count) == expected
    assert resolve_target_fpr(benign_count) == expected


def test_madar_family_aware_replay():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(300, 15))
    y = np.array([0] * 100 + [1] * 200, dtype=int)
    families = ["unknown"] * 100 + ["famA"] * 100 + ["famB"] * 80 + ["famC"] * 20
    idx = build_madar_replay(
        X, y, families, total_budget=100, class_ratio=0.5, budget_strategy="ratio"
    )
    assert 45 <= np.sum(y[idx] == 0) <= 55


def test_ratio_and_uniform_budget():
    ratio = RatioBudget().allocate({"fam1": 100, "fam2": 50}, 100)
    assert ratio["fam1"] == 67
    assert sum(ratio.values()) == 100
    uniform = UniformBudget().allocate({"fam1": 100, "fam2": 50}, 100)
    assert sum(uniform.values()) == 100


@patch("src.nodes.model_retrain.record_model_update_comparison")
@patch("src.nodes.model_retrain.make_model_version", return_value="v_test")
@patch("src.nodes.model_retrain.madar_retrain")
@patch("src.nodes.model_retrain.ingest_benign_corpus")
def test_model_retrain_calls_madar(mock_ingest, mock_madar, _version, mock_record, tmp_paths):
    mock_madar.return_value = {
        "threshold": 0.42,
        "model": "m",
        "model_version": "v_test",
        "evaluation_mode": "strict_temporal_holdout",
        "strict_holdout_excluded": True,
    }
    out = model_retrain(
        AgentState(new_labeled_batch=[{"sha256": "f" * 64, "label": 1, "avg_section_entropy": 1.0}])
    )
    mock_madar.assert_called_once()
    assert mock_madar.call_args.kwargs["init_model"] is None
    assert mock_madar.call_args.kwargs["model_metadata"]["evaluation_mode"] == "strict_temporal_holdout"
    assert mock_madar.call_args.kwargs["model_metadata"]["strict_holdout_excluded"] is True
    mock_record.assert_called_once()
    assert mock_record.call_args.kwargs["holdout_excluded_from_training"] is True
    assert out["evaluation_metrics"]["retrained"] == 1.0


@patch("src.nodes.model_retrain.record_model_update_comparison")
@patch("src.nodes.model_retrain.make_model_version", return_value="v_test")
@patch("src.nodes.model_retrain.madar_retrain")
def test_model_retrain_excludes_temporal_holdout_from_madar(
    mock_madar, _version, _record, tmp_paths
):
    tracker = tmp_paths["tracker"]
    for i in range(20):
        sha = f"{i:064x}"
        tracker.insert_sample(
            sha,
            f"/tmp/{sha}.bin",
            f"2024-01-{i + 1:02d} 00:00:00",
            features={name: float(i) for name in FEATURE_NAMES},
            label=i % 2,
        )
    mock_madar.return_value = {
        "threshold": 0.42,
        "model": "m",
        "model_version": "v_test",
        "evaluation_mode": "strict_temporal_holdout",
        "strict_holdout_excluded": True,
    }
    out = model_retrain(
        AgentState(
            new_labeled_batch=[
                {"sha256": f"{0:064x}", "label": 0, "avg_section_entropy": 0.0},
                {"sha256": f"{17:064x}", "label": 1, "avg_section_entropy": 17.0},
            ]
        )
    )
    historical_features, new_features, historical_labels, new_labels = mock_madar.call_args.args[:4]
    assert len(historical_features) == 16
    assert {f["avg_section_entropy"] for f in historical_features} == set(range(1, 17))
    assert [f["sha256"] for f in new_features] == [f"{0:064x}"]
    assert len(historical_labels) == 16
    assert new_labels == [0]
    assert out["evaluation_metrics"]["holdout_excluded_count"] == 3.0


@patch("src.nodes.model_retrain.record_model_update_comparison")
@patch("src.nodes.model_retrain.madar_retrain")
def test_model_retrain_skips_unlabeled(mock_madar, mock_record):
    out = model_retrain(AgentState(new_labeled_batch=[{"sha256": "a" * 64}]))
    mock_madar.assert_not_called()
    mock_record.assert_not_called()
    assert out["evaluation_metrics"]["retrained"] == 0.0


@patch("src.ml.classifier.lgb.LGBMClassifier")
@patch("src.ml.classifier.load_bundle", return_value={"model": "existing", "threshold": 0.7})
def test_retrain_reuses_bundle_single_class(mock_load, mock_lgb):
    X = np.ones((8, len(FEATURE_NAMES)))
    y = np.ones(8, dtype=int)
    assert retrain_model(X, y) == {"model": "existing", "threshold": 0.7}
    mock_lgb.assert_not_called()


@patch("src.ml.classifier.predict_proba", return_value=np.array([0.5] * 20))
@patch("src.ml.classifier._fit_lightgbm")
@patch("src.ml.classifier._save_bundle_dict")
@patch("src.ml.classifier.load_bundle")
def test_continue_training(mock_load, mock_save, mock_fit, _mock_proba):
    X = np.random.normal(size=(100, 10))
    y = np.array([0] * 50 + [1] * 50)
    old_model = MagicMock()
    old_model.booster_.num_trees.return_value = 150
    old_model.get_params.return_value = {"n_estimators": 150, "learning_rate": 0.05}
    old_bundle = {
        "model": old_model,
        "selected_feature_indices": list(range(10)),
        "selected_feature_names": [f"f{i}" for i in range(10)],
        "threshold": 0.5,
    }
    mock_load.return_value = old_bundle
    with patch("src.config.CONTINUATION_TREES", 50), patch("src.config.MAX_TOTAL_TREES", 500):
        continue_training(X, y, X[:20], y[:20], old_bundle=old_bundle)
    assert mock_fit.call_args.kwargs["init_model"] == old_model


@patch("src.ml.madar.retrain_model")
@patch("src.ml.madar.continue_training", return_value={"model_version": "v_continued"})
def test_madar_continuation_uses_distinct_validation_split(mock_continue, mock_retrain):
    features = [{name: float(i) for name in FEATURE_NAMES} for i in range(40)]
    labels = [i % 2 for i in range(40)]
    init_bundle = {
        "model": object(),
        "threshold": 0.5,
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_dim": FEATURE_DIM,
        "feature_names": FEATURE_NAMES,
        "selected_feature_indices": list(range(10)),
        "selected_feature_names": FEATURE_NAMES[:10],
    }
    madar_retrain([], features, [], labels, init_model=init_bundle)
    mock_continue.assert_called_once()
    X_train, y_train, X_val, y_val = mock_continue.call_args.args[:4]
    assert len(y_train) == 34
    assert len(y_val) == 6
    assert not np.array_equal(X_train, X_val)
    assert len(np.unique(y_train)) == 2
    assert len(np.unique(y_val)) == 2
    mock_retrain.assert_not_called()


@patch("src.ml.features.features_to_vector", return_value=np.zeros(2304))
@patch("src.evaluation.tesseract.model_bundle_ready", return_value=True)
@patch("src.evaluation.tesseract.load_bundle")
@patch("src.evaluation.tesseract.score_feature_matrix")
@patch("src.db.tracker.get_tracker")
def test_retrograde_eval(mock_get_tracker, mock_score, mock_load, _ready, _vec):
    mock_tracker = MagicMock()
    mock_get_tracker.return_value = mock_tracker
    mock_tracker.get_all_task_ids.return_value = [1, 2]
    mock_tracker.fetch_task_holdout.side_effect = [
        [
            {"features": {"avg_section_entropy": 0.5}, "label": 1},
            {"features": {"avg_section_entropy": 0.2}, "label": 0},
        ],
        [{"features": {"avg_section_entropy": 0.9}, "label": 1}],
    ]
    mock_load.return_value = {
        "model": MagicMock(),
        "threshold": 0.5,
        "feature_dim": 2304,
        "feature_set_version": "ember_static_v1",
        "feature_names": ["f1"] * 2304,
    }
    mock_score.side_effect = [np.array([0.9, 0.1]), np.array([0.2])]
    metrics = run_retrograde_eval(mock_tracker)
    assert metrics["task_1_accuracy"] == 1.0
    assert round(metrics["retrograde_accuracy"], 2) == 0.67


@patch("src.ml.classifier.lgb.LGBMClassifier")
def test_cold_start_skips_single_class(mock_lgb, tmp_paths):
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


@patch("src.ml.services.classifier_service.retrain_model")
def test_retrain_service_delegates(mock_retrain):
    X = np.zeros((10, FEATURE_DIM))
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    mock_retrain.return_value = {"threshold": 0.42}
    assert RetrainService().retrain(X, y)["threshold"] == 0.42

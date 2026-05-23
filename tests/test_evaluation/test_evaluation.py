"""TESSERACT evaluation and evaluation node."""

import json
from unittest.mock import patch

import numpy as np

from src.config import FEATURE_DIM, FEATURE_NAMES, FEATURE_SET_VERSION
from src.evaluation.model_update import (
    append_model_update_log,
    build_model_update_record,
    record_model_update_comparison,
)
from src.evaluation.tesseract import append_eval_log, plot_performance_decay, run_tesseract_eval
from src.nodes.evaluation_node import evaluation_node
from src.state import AgentState


def _features(value: float) -> dict[str, float]:
    return {name: value for name in FEATURE_NAMES}


def _explicit_holdout(labels: list[int] | None = None) -> dict:
    y = np.array(labels if labels is not None else [1, 0, 1], dtype=int)
    return {
        "evaluation_mode": "strict_temporal_holdout",
        "x": np.zeros((len(y), FEATURE_DIM)),
        "y": y,
        "hashes": [f"h{i}" for i in range(len(y))],
        "healthy": len(np.unique(y)) == 2,
        "summary": {
            "support": 20,
            "holdout_support": len(y),
            "test_benign": int(np.sum(y == 0)),
            "test_malware": int(np.sum(y == 1)),
            "healthy": len(np.unique(y)) == 2,
        },
        "reason": "" if len(np.unique(y)) == 2 else "single_class_holdout",
    }


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
def test_run_tesseract_eval_writes_aut(mock_bundle, mock_fit, mock_score, mock_aut, tmp_paths):
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
    assert run_tesseract_eval(tracker)["aut"] == 0.75


def test_training_order_uses_ingested_at(tmp_paths):
    tracker = tmp_paths["tracker"]
    benign_sha, malware_sha = "b" * 64, "c" * 64
    tracker.insert_sample(
        malware_sha,
        f"/tmp/{malware_sha}.bin",
        "2020-01-01 00:00:00",
        features=_features(1.0),
        label=1,
        ingested_at="2024-01-02 00:00:00",
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
    assert [r["sha256"] for r in rows] == [benign_sha, malware_sha]


@patch("src.evaluation.model_update.model_bundle_ready", return_value=True)
@patch("src.evaluation.model_update.score_feature_matrix")
def test_model_update_record_compares_previous_and_updated(mock_score, _ready, tmp_paths):
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
    mock_score.side_effect = [
        np.array([0.9, 0.9, 0.1]),
        np.array([0.9, 0.1, 0.9]),
    ]
    record = build_model_update_record(
        trigger="threshold_retrain",
        previous_bundle={"threshold": 0.5},
        updated_bundle={"threshold": 0.5, "model_version": "v_test"},
        model_version="v_test",
        tracker=tracker,
    )
    assert record["status"] == "ok"
    assert record["previous_metrics"]["accuracy"] < record["updated_metrics"]["accuracy"]
    assert record["delta_metrics"]["fpr"] < 0
    assert record["evaluation_mode"] == "strict_temporal_holdout"


@patch("src.evaluation.model_update.model_bundle_ready", return_value=True)
@patch("src.evaluation.model_update.score_feature_matrix", return_value=np.array([0.9, 0.1, 0.9]))
def test_model_update_record_baseline_created(_score, _ready, tmp_paths):
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
    record = build_model_update_record(
        trigger="cold_start",
        previous_bundle=None,
        updated_bundle={"threshold": 0.5, "model_version": "v_start"},
        model_version="v_start",
        tracker=tracker,
    )
    assert record["status"] == "baseline_created"
    assert record["previous_metrics"] == {}
    assert record["updated_metrics"]["recall"] == 1.0


@patch("src.evaluation.model_update.build_training_arrays", side_effect=AssertionError("split recomputed"))
@patch("src.evaluation.model_update.model_bundle_ready", return_value=True)
@patch("src.evaluation.model_update.score_feature_matrix")
def test_model_update_record_uses_supplied_strict_holdout(mock_score, _ready, _arrays, tmp_paths):
    mock_score.side_effect = [
        np.array([0.9, 0.9, 0.1]),
        np.array([0.9, 0.1, 0.9]),
    ]
    record = build_model_update_record(
        trigger="drift_detected",
        previous_bundle={"threshold": 0.5, "model_version": "v_prev"},
        updated_bundle={
            "threshold": 0.5,
            "model_version": "v_strict",
            "evaluation_mode": "strict_temporal_holdout",
            "strict_holdout_excluded": True,
        },
        model_version="v_strict",
        tracker=tmp_paths["tracker"],
        holdout=_explicit_holdout(),
        holdout_excluded_from_training=True,
    )
    assert record["status"] == "ok"
    assert record["holdout_excluded_from_training"] is True
    assert record["previous_model_strict"] is False
    assert record["updated_model_strict"] is True
    assert record["holdout"]["hashes"] == ["h0", "h1", "h2"]


@patch("src.evaluation.model_update.build_training_arrays", side_effect=AssertionError("split recomputed"))
def test_model_update_record_skips_single_class_supplied_holdout(_arrays, tmp_paths):
    record = build_model_update_record(
        trigger="threshold_retrain",
        previous_bundle={"threshold": 0.5},
        updated_bundle={
            "threshold": 0.5,
            "model_version": "v_test",
            "evaluation_mode": "strict_temporal_holdout",
            "strict_holdout_excluded": True,
        },
        model_version="v_test",
        tracker=tmp_paths["tracker"],
        holdout=_explicit_holdout([1, 1, 1]),
        holdout_excluded_from_training=True,
    )
    assert record["status"] == "skipped_unhealthy_holdout"
    assert record["skip_reason"] == "single_class_holdout"
    assert record["updated_model_strict"] is True


@patch("src.evaluation.model_update.build_training_arrays", side_effect=AssertionError("split recomputed"))
@patch("src.evaluation.model_update.log_model_update_summary")
@patch("src.evaluation.model_update.append_model_update_log")
@patch("src.evaluation.model_update.model_bundle_ready", return_value=True)
@patch("src.evaluation.model_update.score_feature_matrix", return_value=np.array([0.9, 0.1, 0.9]))
def test_record_model_update_comparison_persists_supplied_holdout(
    _score, _ready, mock_append, _log, _arrays, tmp_paths
):
    record = record_model_update_comparison(
        trigger="drift_detected",
        previous_bundle=None,
        updated_bundle={
            "threshold": 0.5,
            "model_version": "v_strict",
            "evaluation_mode": "strict_temporal_holdout",
            "strict_holdout_excluded": True,
        },
        model_version="v_strict",
        tracker=tmp_paths["tracker"],
        holdout=_explicit_holdout(),
        holdout_excluded_from_training=True,
    )
    mock_append.assert_called_once()
    assert mock_append.call_args.args[0]["holdout"]["hashes"] == ["h0", "h1", "h2"]
    assert record["status"] == "baseline_created"


def test_model_update_record_skips_unhealthy_holdout(tmp_paths):
    tracker = tmp_paths["tracker"]
    for i in range(4):
        sha = f"{i:064x}"
        tracker.insert_sample(
            sha,
            f"/tmp/{sha}.bin",
            f"2024-01-{i + 1:02d} 00:00:00",
            features=_features(float(i)),
            label=i % 2,
        )
    record = build_model_update_record(
        trigger="threshold_retrain",
        previous_bundle={"threshold": 0.5},
        updated_bundle={"threshold": 0.5, "model_version": "v_test"},
        model_version="v_test",
        tracker=tracker,
    )
    assert record["status"] == "skipped_unhealthy_holdout"
    assert record["updated_metrics"] == {}


def test_append_model_update_log(tmp_paths):
    path = tmp_paths["db"].parent / "model_update.jsonl"
    append_model_update_log(
        {
            "timestamp": "2024-01-01T00:00:00+00:00",
            "event": "model_update_comparison",
            "status": "ok",
        },
        path=path,
    )
    assert json.loads(path.read_text().strip())["event"] == "model_update_comparison"


def test_plot_performance_decay_uses_figures_dir(tmp_path, tmp_paths):
    from src.config import FIGURES_DIR

    append_eval_log({"accuracy": 0.9, "fpr": 0.01})
    out_path = plot_performance_decay()
    assert out_path == FIGURES_DIR / "performance_decay.png"
    assert out_path.exists()


@patch("src.evaluation.tesseract.run_tesseract_eval")
def test_evaluation_node_skips_before_interval(mock_eval, tmp_path):
    from src.config import EVAL_STATE_PATH

    EVAL_STATE_PATH.write_text(json.dumps({"runs": 6}), encoding="utf-8")
    with patch("src.nodes.evaluation_node.EVAL_EVERY_RUNS", 10):
        evaluation_node(AgentState(collection_phase="steady"))
    assert json.loads(EVAL_STATE_PATH.read_text())["runs"] == 7
    mock_eval.assert_not_called()


@patch("src.evaluation.tesseract.run_retrograde_eval", return_value={})
@patch("src.evaluation.tesseract.plot_performance_decay")
@patch("src.evaluation.tesseract.append_eval_log")
@patch("src.evaluation.tesseract.run_tesseract_eval", return_value={"accuracy": 0.91, "fpr": 0.002})
def test_evaluation_node_runs_on_interval(mock_eval, mock_append, mock_plot, _retro, tmp_path):
    from src.config import EVAL_STATE_PATH

    EVAL_STATE_PATH.write_text(json.dumps({"runs": 9}), encoding="utf-8")
    with patch("src.nodes.evaluation_node.EVAL_EVERY_RUNS", 10):
        out = evaluation_node(AgentState(collection_phase="steady"))
    assert out["evaluation_metrics"]["accuracy"] == 0.91
    mock_eval.assert_called_once()


@patch("src.nodes.evaluation_node.append_drift_log")
@patch("src.evaluation.tesseract.plot_performance_decay")
@patch("src.evaluation.tesseract.append_eval_log")
@patch("src.evaluation.tesseract.run_tesseract_eval", return_value={"accuracy": 0.88, "fpr": 0.003})
def test_evaluation_node_logs_drift_when_pending(
    mock_eval, mock_append, mock_plot, mock_drift_log
):
    out = evaluation_node(
        AgentState(
            pending_drift_log=True,
            drift_pre_metrics={"accuracy": 0.8},
            drift_stats={"mean_shift": 1.2},
            evaluation_metrics={"retrained": 1.0},
        )
    )
    assert out["pending_drift_log"] is False
    record = mock_drift_log.call_args[0][0]
    assert record["pre_metrics"]["accuracy"] == 0.8

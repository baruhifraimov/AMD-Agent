"""Tests for report figure generation and narrative."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from src.evaluation.drift_log import build_drift_record
from src.evaluation.report_figures import (
    generate_all_figures,
    plot_drift_pre_post_delta,
    plot_performance_decay,
    plot_retrain_delta_bars,
)
from src.evaluation.report_narrative import (
    analyze_performance_decay,
    analyze_retrain_delta,
    build_report_markdown,
    write_report_narrative,
)
from src.state import AgentState


def _write_eval_log(path: Path) -> None:
    rows = [
        {
            "timestamp": "2026-05-23T10:00:00+00:00",
            "trigger": "periodic",
            "metrics": {"accuracy": 0.90, "fpr": 0.02},
        },
        {
            "timestamp": "2026-05-23T12:00:00+00:00",
            "trigger": "retrain_eval",
            "metrics": {"accuracy": 0.85, "fpr": 0.03},
        },
        {
            "timestamp": "2026-05-23T14:00:00+00:00",
            "trigger": "retrain_eval",
            "metrics": {"accuracy": 0.95, "fpr": 0.01},
        },
    ]
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _write_model_update_log(path: Path) -> None:
    rows = [
        {
            "timestamp": "2026-05-23T11:00:00+00:00",
            "status": "ok",
            "trigger": "drift_detected",
            "previous_metrics": {"accuracy": 0.90, "fpr": 0.02},
            "updated_metrics": {"accuracy": 0.95, "fpr": 0.01},
            "delta_metrics": {"accuracy": 0.05, "fpr": -0.01},
        },
        {
            "timestamp": "2026-05-23T13:00:00+00:00",
            "status": "ok",
            "trigger": "drift_detected",
            "previous_metrics": {"accuracy": 0.88, "fpr": 0.04},
            "updated_metrics": {"accuracy": 0.93, "fpr": 0.02},
            "delta_metrics": {"accuracy": 0.05, "fpr": -0.02},
        },
    ]
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _write_drift_log(path: Path) -> None:
    rows = [
        {
            "timestamp": "2026-05-23T11:30:00+00:00",
            "pre_metrics": {"accuracy": 0.85, "fpr": 0.03},
            "post_metrics": {"accuracy": 0.95, "fpr": 0.01},
            "delta_metrics": {"accuracy": 0.10, "fpr": -0.02},
        },
        {
            "timestamp": "2026-05-23T13:30:00+00:00",
            "pre_metrics": {"accuracy": 0.80, "fpr": 0.05},
            "post_metrics": {"accuracy": 0.90, "fpr": 0.02},
            "delta_metrics": {"accuracy": 0.10, "fpr": -0.03},
        },
    ]
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _write_training_history(path: Path) -> None:
    rows = [
        {
            "timestamp": "2026-05-23T11:00:00+00:00",
            "madar_replay_selected": 120,
            "sample_count": 15,
            "metrics": {"accuracy": 0.95, "fpr": 0.01},
            "previous": {"accuracy": 0.90, "fpr": 0.02},
        }
    ]
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _write_sqlite(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE samples (
            sha256 TEXT PRIMARY KEY,
            status TEXT,
            label INTEGER,
            source_provider TEXT,
            ingested_at TEXT,
            acquired_at TEXT
        )
        """
    )
    conn.executemany(
        "INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("a" * 64, "active", 1, "malwarebazaar", "2026-05-23T10:00:00", ""),
            ("b" * 64, "active", 0, "sysinternals", "2026-05-23T10:00:00", ""),
            ("c" * 64, "active", 1, "threatfox", "2026-05-24T10:00:00", ""),
        ],
    )
    conn.commit()
    conn.close()


@pytest.fixture
def report_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data = tmp_path / "data"
    report = tmp_path / "report" / "figures"
    data.mkdir(parents=True)
    report.mkdir(parents=True)

    eval_log = data / "evaluation_log.jsonl"
    model_log = data / "model_update_log.jsonl"
    drift_log = data / "drift_log.jsonl"
    hist_log = data / "training_history.jsonl"
    db_path = data / "malware_tracker.db"

    _write_eval_log(eval_log)
    _write_model_update_log(model_log)
    _write_drift_log(drift_log)
    _write_training_history(hist_log)
    _write_sqlite(db_path)

    monkeypatch.setattr("src.config.EVAL_LOG_PATH", eval_log)
    monkeypatch.setattr("src.config.MODEL_UPDATE_LOG_PATH", model_log)
    monkeypatch.setattr("src.config.DRIFT_LOG_PATH", drift_log)
    monkeypatch.setattr("src.config.TRAINING_HISTORY_PATH", hist_log)
    monkeypatch.setattr("src.config.DB_PATH", db_path)
    monkeypatch.setattr("src.config.FIGURES_DIR", report)
    monkeypatch.setattr("src.config.LEGACY_FIGURES_DIR", data / "figures")
    monkeypatch.setattr("src.config.REPORT_DIR", tmp_path / "report")
    monkeypatch.setattr("src.config.REPORT_NARRATIVE_PATH", tmp_path / "report" / "REPORT.md")

    return {
        "figures_dir": report,
        "eval_log": eval_log,
        "narrative": tmp_path / "report" / "REPORT.md",
    }


def test_plot_functions_create_pngs(report_paths: dict) -> None:
    out = report_paths["figures_dir"]
    for plot_fn in (
        plot_performance_decay,
        plot_retrain_delta_bars,
        plot_drift_pre_post_delta,
    ):
        path = plot_fn(out)
        assert path.exists()
        assert path.stat().st_size > 0


def test_generate_all_figures(report_paths: dict) -> None:
    paths = generate_all_figures(report_paths["figures_dir"], backfill=False)
    assert len(paths) == 6
    for path in paths.values():
        assert path.exists()
        assert path.stat().st_size > 0


def test_narrative_contains_improvement_stats(report_paths: dict) -> None:
    decay = analyze_performance_decay(report_paths["eval_log"])
    assert decay["count"] == 3
    assert decay["max_acc"] == pytest.approx(0.95)

    retrain = analyze_retrain_delta()
    assert retrain["count"] == 2
    assert retrain["mean_acc_delta_pp"] == pytest.approx(5.0)

    md = build_report_markdown()
    assert "+5.0 pp" in md or "5.0 pp" in md
    assert "accuracy" in md.lower()

    path = write_report_narrative(report_paths["narrative"])
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "Figure 4" in text
    assert "Figure 5" in text


def test_build_drift_record_includes_delta_metrics() -> None:
    state = AgentState(
        drift_pre_metrics={"accuracy": 0.80, "fpr": 0.05},
        evaluation_metrics={"new_batch_size": 10.0, "retrained": 1.0},
    )
    record = build_drift_record(state, post_metrics={"accuracy": 0.90, "fpr": 0.02})
    assert record["delta_metrics"]["accuracy"] == pytest.approx(0.10)
    assert record["delta_metrics"]["fpr"] == pytest.approx(-0.03)

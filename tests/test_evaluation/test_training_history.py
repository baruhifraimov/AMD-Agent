"""Tests for src/evaluation/training_history.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.evaluation import training_history as th


def test_count_retrains_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "missing.jsonl"
    assert th.count_retrains(path=p) == 0


def test_read_last_history_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "missing.jsonl"
    assert th.read_last_history(path=p) is None


def test_read_last_history_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert th.read_last_history(path=p) is None
    assert th.count_retrains(path=p) == 0


def test_append_and_read_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "history.jsonl"
    monkeypatch.setattr("src.config.TRAINING_HISTORY_PATH", p)
    monkeypatch.setattr("src.config.ensure_dirs", lambda: None)

    record_a = {"retrain_count": 1, "metrics": {"accuracy": 0.9}}
    record_b = {"retrain_count": 2, "metrics": {"accuracy": 0.92}}
    th.append_history(record_a)
    th.append_history(record_b)

    assert th.count_retrains() == 2
    last = th.read_last_history()
    assert last == record_b


def test_append_skips_blank_lines(tmp_path: Path) -> None:
    p = tmp_path / "history.jsonl"
    p.write_text(json.dumps({"retrain_count": 1}) + "\n\n\n", encoding="utf-8")
    assert th.count_retrains(path=p) == 1
    last = th.read_last_history(path=p)
    assert last == {"retrain_count": 1}


def test_compute_delta_pct_baseline() -> None:
    current = {"accuracy": 0.9, "precision": 0.85, "recall": 0.95}
    deltas = th.compute_delta_pct(current, None)
    assert deltas == {"accuracy": 0.0, "precision": 0.0, "recall": 0.0}


def test_compute_delta_pct_improvement() -> None:
    current = {"accuracy": 0.95, "precision": 0.9, "recall": 0.94}
    previous = {"accuracy": 0.9, "precision": 0.8, "recall": 0.9}
    deltas = th.compute_delta_pct(current, previous)
    assert deltas["accuracy"] == pytest.approx((0.95 - 0.9) / 0.9 * 100.0)
    assert deltas["precision"] == pytest.approx((0.9 - 0.8) / 0.8 * 100.0)
    assert deltas["recall"] == pytest.approx((0.94 - 0.9) / 0.9 * 100.0)


def test_compute_delta_pct_regression() -> None:
    current = {"accuracy": 0.85}
    previous = {"accuracy": 0.9}
    deltas = th.compute_delta_pct(current, previous)
    assert deltas["accuracy"] < 0.0


def test_compute_delta_pct_zero_previous() -> None:
    current = {"accuracy": 0.5}
    previous = {"accuracy": 0.0}
    deltas = th.compute_delta_pct(current, previous)
    assert deltas["accuracy"] == 0.0

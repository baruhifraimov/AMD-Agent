"""Tests for MADAR replay buffer."""

import numpy as np

from src.ml.madar import build_replay_indices


def test_replay_buffer_split():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(500, 15))
    idx = build_replay_indices(X, budget=200)
    assert len(idx) <= 200
    assert len(idx) >= 1


def test_class_balanced_replay_includes_both_labels():
    rng = np.random.default_rng(7)
    n = 200
    X = rng.normal(size=(n, 15))
    y = np.array([0] * 100 + [1] * 100, dtype=int)
    idx = build_replay_indices(X, y, budget=80)
    assert len(idx) <= 80
    replay_labels = y[idx]
    assert 0 in replay_labels
    assert 1 in replay_labels

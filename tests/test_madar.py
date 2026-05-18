"""Tests for MADAR replay buffer."""

import numpy as np

from src.ml.madar import build_replay_indices


def test_replay_buffer_split():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(500, 15))
    idx = build_replay_indices(X, budget=200)
    assert len(idx) <= 200
    assert len(idx) >= 1

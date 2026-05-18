"""MADAR exact-replay continual learning with Isolation Forest sampling."""

from __future__ import annotations

import logging

import numpy as np
from sklearn.ensemble import IsolationForest

from src.config import REPLAY_BUDGET
from src.ml.classifier import retrain_model
from src.ml.features import features_to_vector, vectorize_batch

logger = logging.getLogger(__name__)


def build_replay_indices(
    X_hist: np.ndarray,
    budget: int = REPLAY_BUDGET,
    contamination: float = 0.2,
) -> np.ndarray:
    """Select 80% core (low anomaly) + 20% outliers (high anomaly)."""
    if len(X_hist) == 0:
        return np.array([], dtype=int)
    budget = min(budget, len(X_hist))
    iso = IsolationForest(contamination=contamination, random_state=42)
    iso.fit(X_hist)
    scores = -iso.decision_function(X_hist)  # higher = more anomalous
    order = np.argsort(scores)
    n_core = int(budget * 0.8)
    n_outlier = budget - n_core
    core_idx = order[:n_core]
    outlier_idx = order[-n_outlier:] if n_outlier else np.array([], dtype=int)
    return np.unique(np.concatenate([core_idx, outlier_idx]))


def madar_retrain(
    historical_features: list[dict],
    new_batch: list[dict],
    historical_labels: list[int],
    new_labels: list[int],
) -> dict:
    """Build replay buffer + new batch, retrain LightGBM."""
    X_hist = vectorize_batch(historical_features) if historical_features else np.empty((0, 0))
    X_new = vectorize_batch(new_batch) if new_batch else np.empty((0, 0))

    if X_hist.size == 0 and X_new.size == 0:
        raise ValueError("No features for MADAR retrain")

    replay_idx = build_replay_indices(X_hist) if len(X_hist) else np.array([], dtype=int)
    X_replay = X_hist[replay_idx] if len(replay_idx) else np.empty((0, X_new.shape[1] if X_new.size else 15))
    y_replay = np.array([historical_labels[i] for i in replay_idx], dtype=int) if len(replay_idx) else np.array([])

    y_new = np.array(new_labels, dtype=int) if new_labels else np.array([])

    if X_replay.size and X_new.size:
        X = np.vstack([X_replay, X_new])
        y = np.concatenate([y_replay, y_new])
    elif X_new.size:
        X, y = X_new, y_new
    else:
        X, y = X_replay, y_replay

    logger.info("MADAR retrain: replay=%d new=%d total=%d", len(replay_idx), len(new_batch), len(y))
    return retrain_model(X, y)

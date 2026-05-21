"""MADAR exact-replay continual learning with Isolation Forest sampling."""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from src.config import FEATURE_NAMES, REPLAY_BUDGET, REPLAY_FRACTION
from src.ml.classifier import _bundle_feature_compatible, load_bundle, retrain_model
from src.ml.features import features_to_vector, vectorize_batch

logger = logging.getLogger(__name__)


def _replay_indices_for_pool(
    X_pool: np.ndarray,
    budget: int,
    contamination: float,
) -> np.ndarray:
    if len(X_pool) == 0 or budget <= 0:
        return np.array([], dtype=int)
    budget = min(budget, len(X_pool))
    iso = IsolationForest(contamination=contamination, random_state=42)
    iso.fit(X_pool)
    scores = -iso.decision_function(X_pool)
    order = np.argsort(scores)
    n_core = int(budget * 0.8)
    n_outlier = budget - n_core
    core_idx = order[:n_core]
    outlier_idx = order[-n_outlier:] if n_outlier else np.array([], dtype=int)
    return np.unique(np.concatenate([core_idx, outlier_idx]))


def build_replay_indices(
    X_hist: np.ndarray,
    y_hist: np.ndarray | None = None,
    budget: int = REPLAY_BUDGET,
    contamination: float = 0.2,
) -> np.ndarray:
    """Select replay rows: ~50/50 per class, 80% core + 20% outliers within each class."""
    if len(X_hist) == 0:
        return np.array([], dtype=int)

    if y_hist is None or len(y_hist) != len(X_hist):
        return _replay_indices_for_pool(X_hist, budget, contamination)

    labels = np.unique(y_hist)
    if len(labels) < 2:
        return _replay_indices_for_pool(X_hist, budget, contamination)

    per_class = max(1, budget // len(labels))
    remainder = max(0, budget - per_class * len(labels))
    selected: list[int] = []
    global_indices = np.arange(len(X_hist))

    for offset, label in enumerate(labels):
        class_budget = per_class + (1 if offset < remainder else 0)
        pool_mask = y_hist == label
        pool_global = global_indices[pool_mask]
        X_pool = X_hist[pool_mask]
        local_idx = _replay_indices_for_pool(X_pool, class_budget, contamination)
        selected.extend(pool_global[local_idx].tolist())

    return np.unique(np.asarray(selected, dtype=int))


def madar_retrain(
    historical_features: list[dict],
    new_batch: list[dict],
    historical_labels: list[int],
    new_labels: list[int],
) -> dict[str, Any] | None:
    """Build replay buffer + new batch, retrain LightGBM."""
    X_hist = vectorize_batch(historical_features) if historical_features else np.empty((0, 0))
    X_new = vectorize_batch(new_batch) if new_batch else np.empty((0, 0))

    if X_hist.size == 0 and X_new.size == 0:
        raise ValueError("No features for MADAR retrain")

    y_hist = np.array(historical_labels, dtype=int) if historical_labels else np.array([])
    replay_budget = min(REPLAY_BUDGET, max(1, int(len(X_hist) * REPLAY_FRACTION))) if len(X_hist) else 0
    replay_idx = (
        build_replay_indices(X_hist, y_hist, budget=replay_budget)
        if replay_budget
        else np.array([], dtype=int)
    )
    n_features = len(FEATURE_NAMES)
    X_replay = X_hist[replay_idx] if len(replay_idx) else np.empty(
        (0, X_new.shape[1] if X_new.size else n_features)
    )
    y_replay = y_hist[replay_idx] if len(replay_idx) else np.array([])

    y_new = np.array(new_labels, dtype=int) if new_labels else np.array([])

    if X_replay.size and X_new.size:
        X = np.vstack([X_replay, X_new])
        y = np.concatenate([y_replay, y_new])
    elif X_new.size:
        X, y = X_new, y_new
    else:
        X, y = X_replay, y_replay

    frozen: list[int] | None = None
    existing = load_bundle()
    if existing and _bundle_feature_compatible(existing):
        raw = existing.get("selected_feature_indices")
        if isinstance(raw, list) and raw:
            frozen = [int(i) for i in raw]

    logger.info("MADAR retrain: replay=%d new=%d total=%d", len(replay_idx), len(new_batch), len(y))
    return retrain_model(X, y, frozen_feature_indices=frozen)

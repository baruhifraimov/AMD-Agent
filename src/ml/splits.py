"""Train/validation split helpers (temporal and stratified)."""

from __future__ import annotations

import numpy as np
from sklearn.model_selection import train_test_split


def temporal_split(
    X: np.ndarray,
    y: np.ndarray,
    *,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.0,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Chronological split by row order (caller must order rows by acquired_at)."""
    n = len(y)
    if n == 0:
        cols = X.shape[1] if X.ndim == 2 else 0
        empty_x = np.empty((0, cols))
        empty_y = np.array([], dtype=y.dtype if y.size else int)
        return empty_x, empty_y, empty_x, empty_y, empty_x, empty_y

    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))
    if test_ratio > 0:
        test_end = int(n * (train_ratio + val_ratio + test_ratio))
    else:
        test_end = n

    train_end = max(1, min(train_end, n)) if n > 1 else train_end
    val_end = max(train_end, min(val_end, n))
    test_end = max(val_end, min(test_end, n))

    X_train, y_train = X[:train_end], y[:train_end]
    X_val, y_val = X[train_end:val_end], y[train_end:val_end]
    X_test, y_test = X[val_end:test_end], y[val_end:test_end]
    return X_train, y_train, X_val, y_val, X_test, y_test


def stratified_split(
    X: np.ndarray,
    y: np.ndarray,
    *,
    val_fraction: float,
    test_fraction: float = 0.0,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Random stratified split (sanity checks / bootstrap holdout only)."""
    indices = np.arange(len(y))
    holdout_fraction = val_fraction + test_fraction
    if holdout_fraction <= 0:
        return X, y, np.empty((0, X.shape[1])), np.array([]), np.empty((0, X.shape[1])), np.array([])

    try:
        train_idx, holdout_idx = train_test_split(
            indices,
            test_size=holdout_fraction,
            stratify=y,
            random_state=42,
        )
        if test_fraction > 0:
            test_share = test_fraction / holdout_fraction
            val_idx, test_idx = train_test_split(
                holdout_idx,
                test_size=test_share,
                stratify=y[holdout_idx],
                random_state=43,
            )
        else:
            val_idx = holdout_idx
            test_idx = np.array([], dtype=int)
    except ValueError:
        train_end = int(len(y) * (1 - holdout_fraction))
        val_end = int(len(y) * (1 - test_fraction))
        train_idx = indices[:train_end]
        val_idx = indices[train_end:val_end]
        test_idx = indices[val_end:]

    return X[train_idx], y[train_idx], X[val_idx], y[val_idx], X[test_idx], y[test_idx]

"""Classifier training facade."""

from __future__ import annotations

from typing import Any

import numpy as np

from src.ml.classifier import cold_start_train, fit_threshold, retrain_model


class ClassifierService:
    def cold_start(self, tracker: Any) -> dict[str, Any] | None:
        return cold_start_train(tracker)

    def retrain(self, X: np.ndarray, y: np.ndarray) -> dict[str, Any] | None:
        return retrain_model(X, y)

    def fit_threshold(
        self,
        y_true: np.ndarray,
        y_score: np.ndarray,
        target_fpr: float | None = None,
    ) -> float:
        if target_fpr is None:
            return fit_threshold(y_true, y_score)
        return fit_threshold(y_true, y_score, target_fpr=target_fpr)

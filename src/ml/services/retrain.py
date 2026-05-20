"""Retrain orchestration — threshold tuned on every successful retrain."""

from __future__ import annotations

from typing import Any

import numpy as np

from src.config import TARGET_FPR
from src.ml.classifier import retrain_model
from src.ml.services.classifier_service import ClassifierService


class RetrainService:
    """Delegates to LightGBM retrain_model (fit_threshold with TARGET_FPR)."""

    def __init__(self, classifier: ClassifierService | None = None) -> None:
        self.classifier = classifier or ClassifierService()

    def retrain(self, X: np.ndarray, y: np.ndarray) -> dict[str, Any] | None:
        return self.classifier.retrain(X, y)

    @property
    def target_fpr(self) -> float:
        return TARGET_FPR

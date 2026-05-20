"""ML service protocols (Strategy / facade contracts)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

import numpy as np


class FeatureExtractor(Protocol):
    def extract(self, path: Path) -> tuple[dict[str, Any] | None, str | None]: ...


class ClassifierTrainer(Protocol):
    def cold_start(self, tracker: Any) -> dict[str, Any] | None: ...

    def retrain(self, X: np.ndarray, y: np.ndarray) -> dict[str, Any] | None: ...

    def fit_threshold(
        self,
        y_true: np.ndarray,
        y_score: np.ndarray,
        target_fpr: float = ...,
    ) -> float: ...


class GroundTruthResolver(Protocol):
    def resolve(
        self,
        sha256: str,
        metadata: dict[str, Any],
        *,
        fallback: int,
        tracker: Any | None = None,
    ) -> int: ...

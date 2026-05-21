"""Drift monitoring service with per-sample verified labeling."""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

from src.config import FEATURE_NAMES
from src.ml.classifier import load_bundle, model_bundle_ready
from src.ml.drift import DriftMonitor
from src.ml.features import features_to_vector
from src.ml.services.ground_truth import GroundTruthResolver

logger = logging.getLogger(__name__)


class DriftMonitorService:
    def __init__(
        self,
        monitor: DriftMonitor | None = None,
        resolver: GroundTruthResolver | None = None,
    ) -> None:
        self.monitor = monitor or DriftMonitor()
        self.resolver = resolver or GroundTruthResolver()

    def update_batch(
        self,
        feature_vectors: list[dict[str, Any]],
        section_entropies: list[float],
        *,
        hash_metadata: dict[str, dict[str, Any]],
    ) -> tuple[bool, list[dict[str, Any]], dict[str, float]]:
        labeled_batch: list[dict[str, Any]] = []
        selected = self._selected_drift_indices()
        any_drift = False

        for feats, entropy in zip(feature_vectors, section_entropies):
            sha = str(feats.get("sha256", "")).lower()
            meta = hash_metadata.get(sha, {})
            vector = self._drift_vector(feats, selected)
            if not self.monitor.update(entropy, vector=vector, observed_at=meta.get("first_seen")):
                continue
            any_drift = True
            label = self.resolver.resolve_label(sha, meta)
            if label is None:
                logger.info(
                    "Drift sample %s skipped: no verified label in DB or metadata",
                    sha[:12] if sha else "?",
                )
                continue
            row = dict(feats)
            row["label"] = label
            labeled_batch.append(row)

        drift_stats = dict(self.monitor.last_stats) if any_drift else {}
        return any_drift, labeled_batch, drift_stats

    @staticmethod
    def _selected_drift_indices() -> list[int]:
        bundle = load_bundle()
        if not model_bundle_ready(bundle):
            return list(range(min(64, len(FEATURE_NAMES))))
        indices = list(bundle.get("selected_feature_indices") or [])
        return indices[: min(64, len(indices))] if indices else list(range(min(64, len(FEATURE_NAMES))))

    @staticmethod
    def _drift_vector(feats: dict[str, Any], selected: list[int]) -> np.ndarray:
        vector = features_to_vector(feats)
        if not selected:
            return vector[:64]
        return vector[np.asarray(selected, dtype=int)]

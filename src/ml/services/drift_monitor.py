"""Drift monitoring service with per-sample verified labeling."""

from __future__ import annotations

import logging
from typing import Any

from src.ml.drift import DriftMonitor
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
    ) -> tuple[bool, list[dict[str, Any]]]:
        labeled_batch: list[dict[str, Any]] = []

        for feats, entropy in zip(feature_vectors, section_entropies):
            if not self.monitor.update(entropy):
                continue
            sha = str(feats.get("sha256", "")).lower()
            meta = hash_metadata.get(sha, {})
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

        return bool(labeled_batch), labeled_batch

"""Collection phase context DTO."""

from __future__ import annotations

from dataclasses import dataclass

import src.db.tracker as db
from src.config import MIN_TRAIN_BENIGN, MIN_TRAIN_MALWARE
from src.ml.classifier import load_bundle, model_bundle_ready


@dataclass(frozen=True)
class CollectionContext:
    benign_count: int
    malware_count: int
    model_ready: bool
    pending_depth: int

    @property
    def phase(self) -> str:
        """Phase from live trainable DB counts only (not model.pkl metadata)."""
        if self.benign_count < MIN_TRAIN_BENIGN or self.malware_count < MIN_TRAIN_MALWARE:
            return "bootstrap"
        return "steady"


def build_collection_context(
    tracker: db.MalwareTracker | None = None,
) -> CollectionContext:
    tracker = tracker or db.get_tracker()
    counts = tracker.count_by_label()
    pending = tracker.fetch_pending_hashes(limit=1)
    return CollectionContext(
        benign_count=counts.get(0, 0),
        malware_count=counts.get(1, 0),
        model_ready=model_bundle_ready(load_bundle()),
        pending_depth=len(pending),
    )


def current_collection_phase(tracker: db.MalwareTracker | None = None) -> str:
    """Return bootstrap or steady for Docker scripts and guards."""
    return build_collection_context(tracker).phase

"""Feature extraction node — pefile static features."""

from __future__ import annotations

import logging
from pathlib import Path

import src.db.tracker as db
from src.ml.features import extract_pe_features
from src.state import AgentState

logger = logging.getLogger(__name__)


def feature_extraction(state: AgentState) -> dict:
    tracker = db.get_tracker()
    vectors: list[dict] = []
    entropies: list[float] = []

    for path in state.downloaded_paths:
        sha = Path(path).stem.lower()
        feats = extract_pe_features(path)
        if feats is None:
            continue
        feats["sha256"] = sha
        vectors.append(feats)
        entropies.append(float(feats.get("avg_section_entropy", 0.0)))
        tracker.update_features(sha, feats)

    logger.info("Extracted features for %d samples", len(vectors))
    return {"feature_vectors": vectors, "section_entropies": entropies}

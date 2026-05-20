"""Feature extraction node — pefile static features."""

from __future__ import annotations

import logging
from pathlib import Path

import src.db.tracker as db
from src.llm import triage_pe_error
from src.ml.features import extract_pe_features_with_error
from src.state import AgentState
from src.tools.update import mark_corrupted, update_features

logger = logging.getLogger(__name__)


def feature_extraction(state: AgentState) -> dict:
    tracker = db.get_tracker()
    vectors: list[dict] = []
    entropies: list[float] = []
    valid_paths: list[str] = []
    valid_hashes: list[str] = []
    feature_errors: dict[str, str] = dict(state.feature_errors)
    rejected = list(state.rejected_candidates)

    for path in state.downloaded_paths:
        sha = Path(path).stem.lower()
        feats, error = extract_pe_features_with_error(path)
        if feats is None:
            message = error or "unknown pefile parse error"
            feature_errors[sha] = message
            meta = state.hash_metadata.get(sha, {})
            decision = triage_pe_error(sha, path, message, meta)
            if decision == "reject":
                mark_corrupted(
                    tracker,
                    sha,
                    message,
                    file_path=path,
                    acquired_at=meta.get("first_seen"),
                    label=int(meta.get("expected_label", state.expected_label)),
                )
                rejected.append(
                    {
                        "sha256": sha,
                        "path": path,
                        "stage": "feature_extraction",
                        "reason": message,
                    }
                )
            continue
        feats["sha256"] = sha
        vectors.append(feats)
        entropies.append(float(feats.get("avg_section_entropy", 0.0)))
        update_features(tracker, sha, feats)
        valid_paths.append(path)
        valid_hashes.append(sha)

    logger.info("Extracted features for %d samples", len(vectors))
    return {
        "downloaded_paths": valid_paths,
        "discovered_hashes": valid_hashes,
        "feature_vectors": vectors,
        "section_entropies": entropies,
        "feature_errors": feature_errors,
        "rejected_candidates": rejected,
    }

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
    rejected_before = len(rejected)
    failed = 0

    for path in state.downloaded_paths:
        sha = Path(path).stem.lower()
        feats, error = extract_pe_features_with_error(path)
        if feats is None:
            failed += 1
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
    rejected_count = len(rejected) - rejected_before
    metrics = dict(state.bootstrap_metrics)
    metrics.update(
        {
            "feature_input": len(state.downloaded_paths),
            "feature_extracted_count": len(vectors),
            "feature_failed": failed,
            "feature_corrupted_count": rejected_count,
            "corrupted_count": int(metrics.get("corrupted_count", 0)) + rejected_count,
        }
    )
    if state.collection_phase == "bootstrap":
        discovery = metrics.get("discovery") or []
        logger.info(
            "Bootstrap pass summary: providers=%s discovered=%d fresh=%d downloaded=%d "
            "pe_valid=%d feature_extracted=%d corrupted=%d",
            ",".join(str(s.get("provider", "")) for s in discovery),
            sum(int(s.get("discovered", 0)) for s in discovery),
            sum(int(s.get("fresh", 0)) for s in discovery),
            int(metrics.get("downloaded_count", 0)),
            int(metrics.get("pe_valid_count", 0)),
            len(vectors),
            int(metrics.get("corrupted_count", 0)),
        )
    return {
        "downloaded_paths": valid_paths,
        "discovered_hashes": valid_hashes,
        "feature_vectors": vectors,
        "section_entropies": entropies,
        "feature_errors": feature_errors,
        "rejected_candidates": rejected,
        "bootstrap_metrics": metrics,
    }

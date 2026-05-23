"""Feature extraction node — pefile static features."""

from __future__ import annotations

from pathlib import Path

import src.db.tracker as db
from src.collection.provider_stats import bump_provider, record_provider_runs
from src.llm import triage_pe_error
from src.log import PHASE_BOOTSTRAP, PHASE_EXTRACTION, get_logger, phase_log, task_status, vlog
from src.ml.features import extract_pe_features_with_error
from src.state import AgentState
from src.tools.update import mark_corrupted, update_features

logger = get_logger(__name__)


def feature_extraction(state: AgentState) -> dict:
    tracker = db.get_tracker()
    vectors: list[dict] = []
    entropies: list[float] = []
    valid_paths: list[str] = []
    valid_hashes: list[str] = []
    feature_errors: dict[str, str] = dict(state.feature_errors)
    rejected = list(state.rejected_candidates)
    rejected_before = len(rejected)
    metrics = dict(state.bootstrap_metrics)
    failed = 0
    n_input = len(state.downloaded_paths)

    with task_status(PHASE_EXTRACTION, f"Extracting features from {n_input} files"):
        for path in state.downloaded_paths:
            sha = Path(path).stem.lower()
            meta = state.hash_metadata.get(sha, {})
            feats, error = extract_pe_features_with_error(path)
            if feats is None:
                failed += 1
                message = error or "unknown pefile parse error"
                feature_errors[sha] = message
                bump_provider(metrics, str(meta.get("source_provider") or ""), meta.get("expected_label"), failed=1)
                candidate_key = str(meta.get("candidate_key") or "")
                if candidate_key:
                    tracker.record_candidate_outcome(candidate_key, status="feature_failed", error=message)
                decision = triage_pe_error(sha, path, message, meta)
                if decision == "reject":
                    mark_corrupted(
                        tracker,
                        sha,
                        message,
                        file_path=path,
                        acquired_at=meta.get("first_seen"),
                        label=int(meta.get("expected_label", state.expected_label)),
                        source_first_seen=meta.get("source_first_seen") or meta.get("first_seen"),
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
            if "malware_family" in meta:
                tracker.update_family(sha, meta["malware_family"])
            bump_provider(metrics, str(meta.get("source_provider") or ""), meta.get("expected_label"), feature_extracted=1)
            candidate_key = str(meta.get("candidate_key") or "")
            if candidate_key:
                tracker.record_candidate_outcome(candidate_key, status="feature_extracted", sha256=sha)
            valid_paths.append(path)
            valid_hashes.append(sha)

    rejected_count = len(rejected) - rejected_before
    phase_log(
        logger,
        PHASE_EXTRACTION,
        "Done: %d extracted, %d failed (%d input)",
        len(vectors),
        failed,
        n_input,
    )
    metrics.update(
        {
            "feature_input": n_input,
            "feature_extracted_count": len(vectors),
            "feature_failed": failed,
            "feature_corrupted_count": rejected_count,
            "corrupted_count": int(metrics.get("corrupted_count", 0)) + rejected_count,
        }
    )
    if state.collection_phase == "bootstrap":
        discovery = metrics.get("discovery") or []
        phase_log(
            logger,
            PHASE_BOOTSTRAP,
            "Pass summary: downloaded=%d pe_valid=%d features=%d corrupted=%d",
            int(metrics.get("downloaded_count", 0)),
            int(metrics.get("pe_valid_count", 0)),
            len(vectors),
            int(metrics.get("corrupted_count", 0)),
        )
        vlog(
            logger,
            "info",
            "Bootstrap discovery providers=%s discovered=%d fresh=%d",
            ",".join(str(s.get("provider", "")) for s in discovery),
            sum(int(s.get("discovered", 0)) for s in discovery),
            sum(int(s.get("fresh", 0)) for s in discovery),
        )
    record_provider_runs(tracker, metrics, phase=state.collection_phase or "unknown")
    return {
        "downloaded_paths": valid_paths,
        "discovered_hashes": valid_hashes,
        "feature_vectors": vectors,
        "section_entropies": entropies,
        "feature_errors": feature_errors,
        "rejected_candidates": rejected,
        "bootstrap_metrics": metrics,
    }

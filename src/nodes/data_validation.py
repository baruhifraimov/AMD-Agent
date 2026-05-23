"""Data validation node — MZ check and SQLite deduplication."""

from __future__ import annotations

import logging
from pathlib import Path

import src.db.tracker as db
from src.collection.provider_stats import bump_provider
from src.state import AgentState
from src.tools.update import insert_sample, mark_corrupted, update_file_path
from src.tools.validate import file_sha256, is_duplicate, is_pe_mz, is_pe_signature

logger = logging.getLogger(__name__)


def data_validation(state: AgentState) -> dict:
    tracker = db.get_tracker()
    valid_paths: list[str] = []
    valid_hashes: list[str] = []
    metrics = dict(state.bootstrap_metrics)
    corrupted = 0
    skipped = 0

    for path in state.downloaded_paths:
        p = Path(path)
        sha = p.stem.lower()
        if len(sha) != 64:
            logger.warning("Skipping invalid path stem: %s", path)
            skipped += 1
            continue
        if tracker.is_corrupted(sha):
            logger.info("Skipping previously corrupted hash: %s", sha)
            meta = state.hash_metadata.get(sha, {})
            bump_provider(metrics, str(meta.get("source_provider") or ""), meta.get("expected_label"), failed=1)
            skipped += 1
            continue
        if not is_pe_mz(path):
            logger.warning("MZ check failed: %s", sha)
            meta = state.hash_metadata.get(sha, {})
            bump_provider(metrics, str(meta.get("source_provider") or ""), meta.get("expected_label"), non_pe=1, failed=1)
            mark_corrupted(
                tracker,
                sha,
                "MZ signature check failed",
                file_path=path,
                acquired_at=meta.get("first_seen"),
                label=int(meta.get("expected_label", state.expected_label)),
                source_first_seen=meta.get("source_first_seen") or meta.get("first_seen"),
            )
            corrupted += 1
            continue
        if not is_pe_signature(path):
            logger.warning("PE signature check failed: %s", sha)
            meta = state.hash_metadata.get(sha, {})
            bump_provider(metrics, str(meta.get("source_provider") or ""), meta.get("expected_label"), non_pe=1, failed=1)
            mark_corrupted(
                tracker,
                sha,
                "PE signature check failed",
                file_path=path,
                acquired_at=meta.get("first_seen"),
                label=int(meta.get("expected_label", state.expected_label)),
                source_first_seen=meta.get("source_first_seen") or meta.get("first_seen"),
            )
            corrupted += 1
            continue
        actual_sha = file_sha256(path)
        if actual_sha != sha:
            logger.warning("SHA256 filename mismatch: path=%s expected=%s actual=%s", path, sha, actual_sha)
            meta = state.hash_metadata.get(sha, {})
            bump_provider(metrics, str(meta.get("source_provider") or ""), meta.get("expected_label"), failed=1)
            mark_corrupted(
                tracker,
                sha,
                f"SHA256 filename mismatch: actual={actual_sha}",
                file_path=path,
                acquired_at=meta.get("first_seen"),
                label=int(meta.get("expected_label", state.expected_label)),
                source_first_seen=meta.get("source_first_seen") or meta.get("first_seen"),
            )
            corrupted += 1
            continue
        if is_duplicate(sha, tracker):
            logger.info("Duplicate hash skipped: %s", sha)
            meta = state.hash_metadata.get(sha, {})
            bump_provider(metrics, str(meta.get("source_provider") or ""), meta.get("expected_label"), duplicate=1)
            skipped += 1
            continue

        meta = state.hash_metadata.get(sha, {})
        ingested = meta.get("ingested_at") or db.MalwareTracker.utc_now_iso()
        label = int(meta.get("expected_label", state.expected_label))
        source_first_seen = meta.get("source_first_seen") or meta.get("first_seen") or None

        if tracker.is_pending(sha):
            update_file_path(
                tracker,
                sha,
                path,
                source_provider=meta.get("source_provider"),
                source_url=meta.get("source_url"),
                ingested_at=ingested,
                source_first_seen=source_first_seen,
            )
            logger.info("Updated pending row with file_path: %s", sha)
        else:
            insert_sample(
                tracker,
                sha,
                path,
                ingested,
                label=label,
                source_provider=meta.get("source_provider"),
                source_url=meta.get("source_url"),
                ingested_at=ingested,
                source_first_seen=source_first_seen,
            )

        bump_provider(metrics, str(meta.get("source_provider") or ""), label, valid_pe=1)
        valid_paths.append(path)
        valid_hashes.append(sha)

    metrics.update(
        {
            "pe_validation_input": len(state.downloaded_paths),
            "pe_valid_count": len(valid_paths),
            "pe_corrupted_count": corrupted,
            "pe_validation_skipped": skipped,
            "corrupted_count": int(metrics.get("corrupted_count", 0)) + corrupted,
        }
    )
    return {
        "downloaded_paths": valid_paths,
        "discovered_hashes": valid_hashes,
        "bootstrap_metrics": metrics,
    }

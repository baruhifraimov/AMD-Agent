"""Data validation node — MZ check and SQLite deduplication."""

from __future__ import annotations

import logging
from pathlib import Path

import src.db.tracker as db
from src.state import AgentState
from src.tools.validate import file_sha256, is_duplicate, is_pe_mz, is_pe_signature

logger = logging.getLogger(__name__)


def data_validation(state: AgentState) -> dict:
    tracker = db.get_tracker()
    valid_paths: list[str] = []
    valid_hashes: list[str] = []

    for path in state.downloaded_paths:
        p = Path(path)
        sha = p.stem.lower()
        if len(sha) != 64:
            logger.warning("Skipping invalid path stem: %s", path)
            continue
        if tracker.is_corrupted(sha):
            logger.info("Skipping previously corrupted hash: %s", sha)
            continue
        if not is_pe_mz(path):
            logger.warning("MZ check failed: %s", sha)
            meta = state.hash_metadata.get(sha, {})
            tracker.mark_corrupted(
                sha,
                "MZ signature check failed",
                file_path=path,
                acquired_at=meta.get("first_seen"),
                label=int(meta.get("expected_label", state.expected_label)),
            )
            continue
        if not is_pe_signature(path):
            logger.warning("PE signature check failed: %s", sha)
            meta = state.hash_metadata.get(sha, {})
            tracker.mark_corrupted(
                sha,
                "PE signature check failed",
                file_path=path,
                acquired_at=meta.get("first_seen"),
                label=int(meta.get("expected_label", state.expected_label)),
            )
            continue
        actual_sha = file_sha256(path)
        if actual_sha != sha:
            logger.warning("SHA256 filename mismatch: path=%s expected=%s actual=%s", path, sha, actual_sha)
            meta = state.hash_metadata.get(sha, {})
            tracker.mark_corrupted(
                sha,
                f"SHA256 filename mismatch: actual={actual_sha}",
                file_path=path,
                acquired_at=meta.get("first_seen"),
                label=int(meta.get("expected_label", state.expected_label)),
            )
            continue
        if is_duplicate(sha, tracker):
            logger.info("Duplicate hash skipped: %s", sha)
            continue

        meta = state.hash_metadata.get(sha, {})
        acquired = meta.get("first_seen") or db.MalwareTracker.utc_now_iso()
        label = int(meta.get("expected_label", state.expected_label))

        if tracker.is_pending(sha):
            tracker.update_file_path(sha, path)
            logger.info("Updated pending row with file_path: %s", sha)
        else:
            tracker.insert_sample(sha, path, acquired, label=label)

        valid_paths.append(path)
        valid_hashes.append(sha)

    return {
        "downloaded_paths": valid_paths,
        "discovered_hashes": valid_hashes,
    }

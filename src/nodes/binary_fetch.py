"""Binary fetch node — download via active provider and hash content."""

from __future__ import annotations

import hashlib
import logging

import src.db.tracker as db
from src.intel.collector import ThreatIntelCollector
from src.sources.base import SampleCandidate
from src.state import AgentState
from src.tools.fetch import save_pe_to_sandbox
from src.tools.pe_download import download_pe_candidate
from src.tools.update import mark_corrupted

logger = logging.getLogger(__name__)


def binary_fetch(state: AgentState) -> dict:
    tracker = db.get_tracker()
    intel = ThreatIntelCollector(tracker=tracker)

    paths: list[str] = []
    hashes: list[str] = []
    metadata: dict = dict(state.hash_metadata)
    failed = 0
    non_pe = 0
    skipped = 0
    corrupted = 0

    for raw in state.sample_candidates:
        candidate = SampleCandidate.from_dict(raw)
        try:
            candidate_sha = str(candidate.download_ref.get("sha256") or candidate.external_id).lower()
            if len(candidate_sha) == 64 and tracker.is_corrupted(candidate_sha):
                logger.info("Skipping previously corrupted sample: %s", candidate_sha)
                skipped += 1
                continue
            if len(candidate_sha) == 64 and tracker.is_downloaded(candidate_sha):
                logger.info("Already downloaded, skipping before fetch: %s", candidate_sha)
                skipped += 1
                continue
            content = download_pe_candidate(candidate)
            if len(content) < 2 or content[:2] != b"MZ":
                logger.warning("Skipping non-PE download: %s", candidate.external_id)
                intel.record_download_outcome(candidate.metadata, success=False)
                non_pe += 1
                ext = candidate.external_id
                if len(ext) == 64:
                    mark_corrupted(
                        tracker,
                        ext,
                        "Downloaded content failed MZ signature check",
                        acquired_at=candidate.metadata.get("first_seen"),
                        label=candidate.expected_label,
                    )
                    corrupted += 1
                continue
            sha = hashlib.sha256(content).hexdigest()
            if tracker.is_corrupted(sha):
                logger.info("Skipping previously corrupted content hash: %s", sha)
                skipped += 1
                continue
            if tracker.is_downloaded(sha):
                logger.info("Already downloaded, skipping: %s", sha)
                skipped += 1
                continue
            path = save_pe_to_sandbox(sha, content)
            paths.append(path)
            hashes.append(sha)
            meta = dict(candidate.metadata)
            meta.setdefault("file_name", candidate.metadata.get("file_name", ""))
            meta["first_seen"] = meta.get("first_seen") or db.MalwareTracker.utc_now_iso()
            meta["expected_label"] = candidate.expected_label
            meta["source_provider"] = candidate.provider
            metadata[sha] = meta
            intel.record_download_outcome(meta, success=True)
        except Exception as exc:
            logger.warning("Download failed for %s: %s", candidate.external_id, exc)
            intel.record_download_outcome(candidate.metadata, success=False)
            failed += 1

    logger.info("Fetched %d/%d binaries", len(paths), len(state.sample_candidates))
    metrics = dict(state.bootstrap_metrics)
    metrics.update(
        {
            "download_attempted": len(state.sample_candidates),
            "downloaded_count": len(paths),
            "download_failed": failed,
            "download_non_pe": non_pe,
            "download_skipped": skipped,
            "corrupted_count": int(metrics.get("corrupted_count", 0)) + corrupted,
        }
    )
    return {
        "downloaded_paths": paths,
        "discovered_hashes": hashes,
        "hash_metadata": metadata,
        "bootstrap_metrics": metrics,
    }

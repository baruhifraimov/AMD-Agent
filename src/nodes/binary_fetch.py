"""Binary fetch node — download via active provider and hash content."""

from __future__ import annotations

import hashlib
import logging

import src.db.tracker as db
from src.sources.base import SampleCandidate
from src.sources.registry import get_registry
from src.state import AgentState
from src.tools.fetch import save_pe_to_sandbox

logger = logging.getLogger(__name__)


def binary_fetch(state: AgentState) -> dict:
    registry = get_registry()
    provider = registry.get(state.source_type)
    tracker = db.get_tracker()

    paths: list[str] = []
    hashes: list[str] = []
    metadata: dict = dict(state.hash_metadata)

    for raw in state.sample_candidates:
        candidate = SampleCandidate.from_dict(raw)
        try:
            content = provider.download(candidate)
            if len(content) < 2 or content[:2] != b"MZ":
                logger.warning("Skipping non-PE download: %s", candidate.external_id)
                continue
            sha = hashlib.sha256(content).hexdigest()
            if tracker.is_downloaded(sha):
                logger.info("Already downloaded, skipping: %s", sha)
                continue
            path = save_pe_to_sandbox(sha, content)
            paths.append(path)
            hashes.append(sha)
            meta = dict(candidate.metadata)
            meta.setdefault("file_name", candidate.metadata.get("file_name", ""))
            meta["first_seen"] = meta.get("first_seen") or db.MalwareTracker.utc_now_iso()
            meta["expected_label"] = state.expected_label
            meta["source_provider"] = state.source_type
            metadata[sha] = meta
        except Exception as exc:
            logger.warning("Download failed for %s: %s", candidate.external_id, exc)

    logger.info("Fetched %d/%d binaries", len(paths), len(state.sample_candidates))
    return {
        "downloaded_paths": paths,
        "discovered_hashes": hashes,
        "hash_metadata": metadata,
    }

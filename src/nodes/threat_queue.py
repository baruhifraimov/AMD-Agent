"""ThreatIngestor pending-hash queue consumer."""

from __future__ import annotations

import logging

import src.db.tracker as db
from src.config import PE_FETCH_LIMIT, THREAT_QUEUE_ENABLED
from src.sources.base import SampleCandidate
from src.state import AgentState

logger = logging.getLogger(__name__)


def consume_threatingestor_queue(state: AgentState) -> dict:
    """
    Load pending malware hashes from SQLite (ThreatIngestor) into sample_candidates.
    """
    if not THREAT_QUEUE_ENABLED:
        return {"sample_candidates": []}

    tracker = db.get_tracker()
    pending = tracker.fetch_pending_hashes(limit=PE_FETCH_LIMIT)

    if not pending:
        logger.info("ThreatIngestor queue empty")
        return {"sample_candidates": []}

    candidates = []
    for row in pending:
        sha = row["sha256"]
        candidates.append(
            SampleCandidate(
                external_id=sha,
                provider="malwarebazaar",
                expected_label=1,
                download_ref={"sha256": sha},
                metadata={
                    "discovery_source": "threatingestor",
                    "first_seen": row.get("acquired_at") or "",
                },
            ).to_dict()
        )

    logger.info("Loaded %d pending hashes from ThreatIngestor queue", len(candidates))
    return {
        "source_type": "malwarebazaar",
        "expected_label": 1,
        "sample_candidates": candidates,
    }

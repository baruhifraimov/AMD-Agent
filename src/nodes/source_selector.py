"""Source selector node — choose malware vs benign provider."""

from __future__ import annotations

import logging

from src.sources.selector import choose_provider
from src.state import AgentState

logger = logging.getLogger(__name__)


def source_selector(state: AgentState) -> dict:
    provider = choose_provider()
    return {
        "source_type": provider.name,
        "expected_label": provider.expected_label,
        "sample_candidates": [],
        "discovered_hashes": [],
        "downloaded_paths": [],
        "feature_vectors": [],
        "predictions": {},
        "section_entropies": [],
        "new_labeled_batch": [],
        "drift_detected": False,
        "hash_metadata": {},
    }

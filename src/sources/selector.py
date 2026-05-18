"""Dataset-aware provider selection for malware vs benign balance."""

from __future__ import annotations

import logging
import os

import src.db.tracker as db
from src.config import (
    BENIGN_PROVIDER_NAMES,
    MIN_BENIGN_FOR_FPR,
    TARGET_MALWARE_BENIGN_RATIO,
)
from src.sources.base import PESourceProvider
from src.sources.registry import SourceRegistry, get_registry

logger = logging.getLogger(__name__)

_BENIGN_ROUND_ROBIN_IDX = 0


def choose_provider(
    registry: SourceRegistry | None = None,
    tracker: db.MalwareTracker | None = None,
) -> PESourceProvider:
    """Pick provider based on SQLite label balance."""
    registry = registry or get_registry()
    tracker = tracker or db.get_tracker()
    counts = tracker.count_by_label()
    n_mal = counts.get(1, 0)
    n_ben = counts.get(0, 0)

    need_benign = n_ben < MIN_BENIGN_FOR_FPR
    if not need_benign and n_ben > 0:
        ratio = n_mal / n_ben
        need_benign = ratio > TARGET_MALWARE_BENIGN_RATIO

    if need_benign:
        provider = _choose_benign_provider(registry)
        logger.info(
            "Source selector: benign (%s) malware=%d benign=%d",
            provider.name,
            n_mal,
            n_ben,
        )
        return provider

    provider = registry.get("malwarebazaar")
    logger.info(
        "Source selector: malware (%s) malware=%d benign=%d",
        provider.name,
        n_mal,
        n_ben,
    )
    return provider


def _choose_benign_provider(registry: SourceRegistry) -> PESourceProvider:
    forced = os.getenv("AMD_BENIGN_PROVIDER", "").strip().lower()
    if forced:
        return registry.get(forced)

    global _BENIGN_ROUND_ROBIN_IDX
    names = [n for n in BENIGN_PROVIDER_NAMES if n in registry.list_names()]
    if not names:
        raise RuntimeError("No benign providers registered")
    name = names[_BENIGN_ROUND_ROBIN_IDX % len(names)]
    _BENIGN_ROUND_ROBIN_IDX += 1
    return registry.get(name)

"""Dataset-aware provider selection for malware vs benign balance."""

from __future__ import annotations

import logging
import os

import src.db.tracker as db
from src.config import (
    BENIGN_PROVIDER_NAMES,
    MIN_TRAIN_BENIGN,
    MIN_TRAIN_MALWARE,
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

    if _next_label(n_mal, n_ben) == 0:
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


def _next_label(n_malware: int, n_benign: int) -> int:
    """Return the class that is most underrepresented for balanced collection."""
    malware_deficit = max(MIN_TRAIN_MALWARE - n_malware, 0)
    benign_deficit = max(MIN_TRAIN_BENIGN - n_benign, 0)

    if malware_deficit or benign_deficit:
        return 0 if benign_deficit >= malware_deficit else 1

    if n_benign == 0:
        return 0
    ratio = n_malware / n_benign
    if ratio > TARGET_MALWARE_BENIGN_RATIO:
        return 0
    if ratio < TARGET_MALWARE_BENIGN_RATIO:
        return 1
    return 1


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

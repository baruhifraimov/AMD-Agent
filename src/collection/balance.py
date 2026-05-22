"""Label-balance helpers for source selection."""

from __future__ import annotations

import os

from src.config import (
    BENIGN_PROVIDER_NAMES,
    MIN_TRAIN_BENIGN,
    MIN_TRAIN_MALWARE,
    TARGET_MALWARE_BENIGN_RATIO,
)
from src.sources.base import PESourceProvider
from src.sources.registry import SourceRegistry

_BENIGN_ROUND_ROBIN_IDX = 0


def next_label(n_malware: int, n_benign: int) -> int:
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


def choose_benign_provider(registry: SourceRegistry) -> PESourceProvider:
    return registry.get(choose_benign_sources(registry)[0])


def choose_benign_sources(registry: SourceRegistry) -> list[str]:
    forced = os.getenv("AMD_BENIGN_PROVIDER", "").strip().lower()
    if forced:
        return [registry.get(forced).name]

    if "benign_net" in registry.list_names():
        try:
            from src.sources.pe_source_store import PESourceStore

            store = PESourceStore()
            if store.list_active_by_type("benign_only", limit=1):
                names = ["benign_net"]
                names.extend(
                    n
                    for n in BENIGN_PROVIDER_NAMES
                    if n in registry.list_names() and n not in names
                )
                return names
        except Exception:
            pass

    global _BENIGN_ROUND_ROBIN_IDX
    names = [n for n in BENIGN_PROVIDER_NAMES if n in registry.list_names()]
    if not names:
        raise RuntimeError("No benign providers registered")
    start = _BENIGN_ROUND_ROBIN_IDX % len(names)
    _BENIGN_ROUND_ROBIN_IDX += 1
    return names[start:] + names[:start]

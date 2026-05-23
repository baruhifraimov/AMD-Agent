"""Label-balance helpers for source selection."""

from __future__ import annotations

import src.db.tracker as db
from src.config import (
    BENIGN_PROVIDER_NAMES,
    FORCED_BENIGN_PROVIDER,
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
    if ratio > TARGET_MALWARE_BENIGN_RATIO * 1.10:
        return 0
    if ratio < TARGET_MALWARE_BENIGN_RATIO * 0.90:
        return 1
    return 1


def choose_benign_provider(
    registry: SourceRegistry,
    tracker: db.MalwareTracker | None = None,
) -> PESourceProvider:
    return registry.get(choose_benign_sources(registry, tracker)[0])


def choose_benign_sources(
    registry: SourceRegistry,
    tracker: db.MalwareTracker | None = None,
) -> list[str]:
    forced = (FORCED_BENIGN_PROVIDER or "").strip().lower()
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
                return _rank_benign_sources(names, tracker)
        except Exception:
            pass

    global _BENIGN_ROUND_ROBIN_IDX
    names = [n for n in BENIGN_PROVIDER_NAMES if n in registry.list_names()]
    if not names:
        raise RuntimeError("No benign providers registered")
    start = _BENIGN_ROUND_ROBIN_IDX % len(names)
    _BENIGN_ROUND_ROBIN_IDX += 1
    return _rank_benign_sources(names[start:] + names[:start], tracker)


def _rank_benign_sources(
    names: list[str],
    tracker: db.MalwareTracker | None = None,
) -> list[str]:
    if not names:
        return names
    tracker = tracker or db.get_tracker()
    ranked = tracker.rank_providers_by_yield(names, 0)
    active = [name for name in ranked if not tracker.is_provider_cooled_down(name, 0)]
    return active or ranked

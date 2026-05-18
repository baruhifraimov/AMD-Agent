"""PE validation and duplicate filtering."""

from __future__ import annotations

from pathlib import Path

import src.db.tracker as db


def is_pe_mz(path: str | Path) -> bool:
    """Check DOS header signature (MZ)."""
    p = Path(path)
    if not p.exists() or p.stat().st_size < 2:
        return False
    with p.open("rb") as f:
        return f.read(2) == b"MZ"


def is_duplicate(sha256: str, tracker: db.MalwareTracker | None = None) -> bool:
    """Return True if SHA256 already exists in tracker DB."""
    store = tracker or db.get_tracker()
    return store.hash_exists(sha256)

"""PE validation and duplicate filtering."""

from __future__ import annotations

import hashlib
from pathlib import Path

import src.db.tracker as db


def is_pe_mz(path: str | Path) -> bool:
    """Check DOS header signature (MZ)."""
    p = Path(path)
    if not p.exists() or p.stat().st_size < 2:
        return False
    with p.open("rb") as f:
        return f.read(2) == b"MZ"


def is_pe_signature(path: str | Path) -> bool:
    """Check DOS MZ header plus PE signature at e_lfanew."""
    p = Path(path)
    if not p.exists() or p.stat().st_size < 0x40:
        return False
    with p.open("rb") as f:
        dos_header = f.read(0x40)
        if len(dos_header) < 0x40 or dos_header[:2] != b"MZ":
            return False
        pe_offset = int.from_bytes(dos_header[0x3C:0x40], "little", signed=False)
        if pe_offset < 0x40 or pe_offset > p.stat().st_size - 4:
            return False
        f.seek(pe_offset)
        return f.read(4) == b"PE\x00\x00"


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_duplicate(sha256: str, tracker: db.MalwareTracker | None = None) -> bool:
    """Return True if SHA256 is already downloaded (pending rows are not duplicates)."""
    store = tracker or db.get_tracker()
    return store.is_downloaded(sha256)

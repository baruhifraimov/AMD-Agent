"""Sandbox file persistence for downloaded PE binaries."""

from __future__ import annotations

import os
from pathlib import Path

from src.config import SANDBOX_DIR, ensure_dirs


def save_pe_to_sandbox(sha256: str, raw_bytes: bytes) -> str:
    """Write PE bytes to sandbox with restrictive permissions.

    Returns:
        Absolute path to saved file.
    """
    ensure_dirs()
    path = SANDBOX_DIR / f"{sha256.lower()}.bin"
    path.write_bytes(raw_bytes)
    os.chmod(path, 0o600)
    return str(path.resolve())


def read_pe_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()

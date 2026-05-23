"""MalShare API — compatibility shim."""

from __future__ import annotations

from typing import Any

from src.config import malshare_enabled
from src.tools.clients.malshare_api_client import MalShareClient, MalShareUnavailable

_client: MalShareClient | None = None


def _get_client() -> MalShareClient:
    global _client
    if _client is None:
        _client = MalShareClient.from_config()
    return _client


def list_pe32_hashes(limit: int = 10) -> list[dict[str, Any]]:
    if not malshare_enabled():
        return []
    return _get_client().list_pe32_hashes(limit=limit)


def download_sample(file_hash: str) -> bytes:
    return _get_client().download(file_hash)

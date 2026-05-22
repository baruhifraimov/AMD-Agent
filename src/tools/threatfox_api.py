"""ThreatFox API — compatibility shim over ThreatFoxClient."""

from __future__ import annotations

from typing import Any

from src.config import get_auth_key
from src.tools.clients.threatfox_api_client import (
    THREATFOX_API_URL,
    ThreatFoxClient,
)

API_URL = THREATFOX_API_URL

_client: ThreatFoxClient | None = None


def _get_client() -> ThreatFoxClient:
    global _client
    if _client is None:
        _client = ThreatFoxClient.from_config()
    return _client


def _extract_sha256(row: dict[str, Any]) -> str | None:
    return ThreatFoxClient._extract_sha256(row)


def get_recent_sha256_hashes(*, days: int = 7, limit: int = 10) -> list[dict[str, Any]]:
    return _get_client().get_recent_sha256_hashes(days=days, limit=limit)


def get_social_sha256_hashes(*, days: int = 7, limit: int = 10) -> list[dict[str, Any]]:
    return _get_client().get_social_sha256_hashes(days=days, limit=limit)

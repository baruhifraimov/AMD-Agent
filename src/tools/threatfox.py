"""ThreatFox API client (abuse.ch) — IOC discovery for malware SHA256 hashes."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from src.config import get_auth_key

logger = logging.getLogger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
SHA256_IOC_TYPES = frozenset({"sha256_hash", "hash", "file_hash", "sha256"})
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SOCIAL_REFERENCE_RE = re.compile(r"(?:twitter\.com|x\.com)", re.I)


def _headers() -> dict[str, str]:
    return {"Auth-Key": get_auth_key()}


def _post(payload: dict[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
    with httpx.Client(timeout=timeout) as client:
        response = client.post(API_URL, json=payload, headers=_headers())
        response.raise_for_status()
        return response.json()


def _extract_sha256(row: dict[str, Any]) -> str | None:
    ioc_type = (row.get("ioc_type") or "").lower()
    ioc = str(row.get("ioc") or "").strip().lower()
    if ioc_type in SHA256_IOC_TYPES and SHA256_RE.fullmatch(ioc):
        return ioc
    if SHA256_RE.fullmatch(ioc):
        return ioc
    nested = row.get("malware_sample") or row.get("malware_samples")
    if isinstance(nested, dict):
        nested = [nested]
    if isinstance(nested, list):
        for item in nested:
            if not isinstance(item, dict):
                continue
            sha = (item.get("sha256_hash") or item.get("sha256") or "").lower()
            if SHA256_RE.fullmatch(sha):
                return sha
    return None


def get_recent_sha256_hashes(*, days: int = 7, limit: int = 10) -> list[dict[str, Any]]:
    """Fetch recent ThreatFox IOCs and return SHA256 hash metadata rows."""
    days = max(1, min(int(days), 7))
    payload = _post({"query": "get_iocs", "days": days})
    if payload.get("query_status") != "ok":
        logger.warning("ThreatFox get_iocs status=%s", payload.get("query_status"))
        return []

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in payload.get("data") or []:
        if not isinstance(row, dict):
            continue
        sha = _extract_sha256(row)
        if not sha or sha in seen:
            continue
        seen.add(sha)
        results.append(
            {
                "sha256": sha,
                "malware": row.get("malware_printable") or row.get("malware") or "",
                "first_seen": row.get("first_seen") or "",
                "threat_type": row.get("threat_type") or "",
            }
        )
        if len(results) >= limit:
            break
    return results


def _is_social_reference(row: dict[str, Any]) -> bool:
    reference = str(row.get("reference") or "")
    return bool(SOCIAL_REFERENCE_RE.search(reference))


def get_social_sha256_hashes(*, days: int = 7, limit: int = 10) -> list[dict[str, Any]]:
    """Fetch ThreatFox IOCs whose reference URL is Twitter/X (open social CTI bridge)."""
    days = max(1, min(int(days), 7))
    payload = _post({"query": "get_iocs", "days": days})
    if payload.get("query_status") != "ok":
        logger.warning("ThreatFox get_iocs (social) status=%s", payload.get("query_status"))
        return []

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in payload.get("data") or []:
        if not isinstance(row, dict) or not _is_social_reference(row):
            continue
        sha = _extract_sha256(row)
        if not sha or sha in seen:
            continue
        seen.add(sha)
        results.append(
            {
                "sha256": sha,
                "malware": row.get("malware_printable") or row.get("malware") or "",
                "first_seen": row.get("first_seen") or "",
                "threat_type": row.get("threat_type") or "",
                "reference": str(row.get("reference") or ""),
            }
        )
        if len(results) >= limit:
            break
    return results

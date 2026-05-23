"""Multi-provider PE download with MalwareBazaar primary and controlled fallbacks."""

from __future__ import annotations

import io
import time
import zipfile
from typing import Any
from urllib.parse import urlparse

import httpx

from src.config import (
    CTI_DOWNLOAD_ALLOWLIST,
    PE_DOWNLOAD_MAX_BYTES,
    get_github_token,
    malshare_enabled,
    mb_fallback_malshare,
)
from src.sources.base import SampleCandidate
from src.sources.registry import get_registry
from src.tools import malwarebazaar_api as mb
from src.tools.cti_search import is_public_url

from src.log import PHASE_FETCH, get_logger, phase_log, vlog

logger = get_logger(__name__)

_MB_RETRIES = 3
_MB_BACKOFF = 2.0


def download_pe_candidate(candidate: SampleCandidate) -> bytes:
    """Download PE bytes: MalwareBazaar, then fallback URL, then provider registry."""
    ref = candidate.download_ref
    sha = str(ref.get("sha256") or "").lower()
    if len(sha) == 64:
        try:
            return _download_mb_with_retry(sha)
        except Exception as exc:
            vlog(logger, "info", "MalwareBazaar download failed for %s: %s", sha, exc)
            if malshare_enabled() and mb_fallback_malshare():
                try:
                    return _download_malshare(sha, ref)
                except Exception as ms_exc:
                    vlog(logger, "info", "MalShare fallback failed for %s: %s", sha, ms_exc)

    fallback = str(ref.get("fallback_url") or "").strip()
    if fallback:
        return _download_direct_url(fallback)

    if candidate.provider and candidate.provider not in (
        "malwarebazaar",
        "intel_direct",
        "malshare",
    ):
        return get_registry().get(candidate.provider).download(candidate)

    if len(sha) == 64:
        raise RuntimeError(f"No download path succeeded for {sha}")
    raise RuntimeError(f"No download path for candidate {candidate.external_id}")


def _download_malshare(sha256: str, ref: dict[str, Any]) -> bytes:
    from src.tools.clients.malshare_api_client import MalShareClient

    client = MalShareClient.from_config()
    h = str(ref.get("hash") or sha256).lower()
    return client.download(h)


def _download_mb_with_retry(sha256: str) -> bytes:
    last_exc: Exception | None = None
    for attempt in range(_MB_RETRIES):
        try:
            return mb.download_sample(sha256)
        except Exception as exc:
            last_exc = exc
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status == 502 and attempt < _MB_RETRIES - 1:
                time.sleep(_MB_BACKOFF * (attempt + 1))
                continue
            if "502" in str(exc) and attempt < _MB_RETRIES - 1:
                time.sleep(_MB_BACKOFF * (attempt + 1))
                continue
            raise
    raise last_exc or RuntimeError(f"MB download failed for {sha256}")


def _host_allowed(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    for allowed in CTI_DOWNLOAD_ALLOWLIST:
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


def _download_direct_url(url: str) -> bytes:
    if not is_public_url(url) or not _host_allowed(url):
        raise RuntimeError(f"Direct download not allowed for URL: {url}")

    headers: dict[str, str] = {}
    token = get_github_token()
    if "github.com" in url and token:
        headers["Authorization"] = f"Bearer {token}"

    with httpx.Client(timeout=180.0, follow_redirects=True) as client:
        with client.stream("GET", url, headers=headers) as response:
            response.raise_for_status()
            content = bytearray()
            for chunk in response.iter_bytes():
                remaining = PE_DOWNLOAD_MAX_BYTES - len(content)
                if remaining <= 0:
                    break
                content.extend(chunk[:remaining])
    data = bytes(content)
    if url.lower().endswith(".zip"):
        return _extract_first_pe_from_zip(data)
    return data


def _extract_first_pe_from_zip(data: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            lower = name.lower()
            if lower.endswith((".exe", ".dll", ".sys", ".scr")):
                return zf.read(name)
    raise RuntimeError("No PE file found inside zip archive")

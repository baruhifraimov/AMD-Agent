"""CTI text extraction helpers with conservative network guardrails."""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from src.config import (
    CTI_HOST_BLOCK_SECONDS_403,
    CTI_HOST_BLOCK_SECONDS_429,
    CTI_HOST_BLOCK_SECONDS_TRANSPORT,
    CTI_PAGE_MAX_BYTES,
    CTI_REQUEST_TIMEOUT,
)

logger = logging.getLogger(__name__)

_host_blocklist: dict[str, float] = {}

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
PE_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+\.(?:exe|dll|sys|scr|zip)(?:\?[^\s\"'<>]*)?",
    re.IGNORECASE,
)
def reset_host_blocklist() -> None:
    """Clear host blocklist (tests only)."""
    _host_blocklist.clear()


def _host_key(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _host_blocked(url: str) -> bool:
    host = _host_key(url)
    if not host:
        return False
    until = _host_blocklist.get(host, 0.0)
    if time.monotonic() < until:
        return True
    if host in _host_blocklist:
        del _host_blocklist[host]
    return False


def _record_host_failure(url: str, status_code: int | None) -> None:
    host = _host_key(url)
    if not host:
        return
    if status_code == 403:
        ttl = CTI_HOST_BLOCK_SECONDS_403
    elif status_code == 429:
        ttl = CTI_HOST_BLOCK_SECONDS_429
    else:
        ttl = CTI_HOST_BLOCK_SECONDS_TRANSPORT
    _host_blocklist[host] = time.monotonic() + ttl
    logger.info("CTI host blocklisted %s for %.0fs (status=%s)", host, ttl, status_code)


def fetch_public_text(url: str) -> str:
    """Fetch a known public CTI URL and return text, bounded by size and timeout."""
    if not is_public_url(url):
        return ""
    if _host_blocked(url):
        logger.debug("CTI fetch skipped (host blocklisted): %s", _host_key(url))
        return ""
    content = bytearray()
    try:
        with httpx.Client(timeout=CTI_REQUEST_TIMEOUT, follow_redirects=True) as client:
            with client.stream("GET", url) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    remaining = CTI_PAGE_MAX_BYTES - len(content)
                    if remaining <= 0:
                        break
                    content.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        break
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status in (403, 429):
            _record_host_failure(url, status)
        logger.warning("CTI page fetch failed for %s: %s", url, exc)
        return ""
    except httpx.TransportError as exc:
        _record_host_failure(url, None)
        logger.warning("CTI page fetch failed for %s: %s", url, exc)
        return ""
    except Exception as exc:
        logger.warning("CTI page fetch failed for %s: %s", url, exc)
        return ""
    soup = BeautifulSoup(bytes(content), "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(" ").split())


def extract_pe_urls(text: str) -> list[str]:
    """Extract direct PE/archive URLs from CTI text."""
    from src.config import CTI_DOWNLOAD_ALLOWLIST

    found: list[str] = []
    seen: set[str] = set()
    for match in PE_URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;)")
        if url in seen or not is_public_url(url):
            continue
        host = (urlparse(url).hostname or "").lower()
        if CTI_DOWNLOAD_ALLOWLIST and not any(
            host == allowed or host.endswith(f".{allowed}") for allowed in CTI_DOWNLOAD_ALLOWLIST
        ):
            continue
        seen.add(url)
        found.append(url)
    return found


def extract_hash_contexts(text: str, *, url: str = "", window: int = 240) -> list[dict[str, str]]:
    """Extract SHA256 hashes with surrounding context for semantic filtering."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in SHA256_RE.finditer(text):
        sha = match.group(0).lower()
        if sha in seen:
            continue
        seen.add(sha)
        start = max(0, match.start() - window)
        end = min(len(text), match.end() + window)
        found.append({"sha256": sha, "url": url, "context": text[start:end]})
    return found


def is_public_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").strip().lower()
    if not host or host in {"localhost", "host.docker.internal"}:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)

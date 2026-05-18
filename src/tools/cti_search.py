"""Dynamic CTI search helpers with conservative network guardrails."""

from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from src.config import CTI_PAGE_MAX_BYTES, CTI_REQUEST_TIMEOUT, CTI_SEARCH_LIMIT

logger = logging.getLogger(__name__)

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def web_search(query: str, limit: int = CTI_SEARCH_LIMIT) -> list[dict[str, str]]:
    """Search public web pages. Returns normalized title/url/snippet rows."""
    try:
        from duckduckgo_search import DDGS
    except Exception as exc:
        logger.info("duckduckgo_search unavailable: %s", exc)
        return []

    rows: list[dict[str, str]] = []
    try:
        with DDGS() as ddgs:
            for result in ddgs.text(query, max_results=limit):
                url = str(result.get("href") or result.get("url") or "")
                if not is_public_url(url):
                    continue
                rows.append(
                    {
                        "title": str(result.get("title") or ""),
                        "url": url,
                        "snippet": str(result.get("body") or ""),
                    }
                )
    except Exception as exc:
        logger.warning("CTI web search failed for %r: %s", query, exc)
    return rows


def fetch_public_text(url: str) -> str:
    """Fetch a public web page and return text, bounded by size and timeout."""
    if not is_public_url(url):
        return ""
    try:
        with httpx.Client(timeout=CTI_REQUEST_TIMEOUT, follow_redirects=True) as client:
            content = bytearray()
            with client.stream("GET", url) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    remaining = CTI_PAGE_MAX_BYTES - len(content)
                    if remaining <= 0:
                        break
                    content.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        break
    except Exception as exc:
        logger.warning("CTI page fetch failed for %s: %s", url, exc)
        return ""
    soup = BeautifulSoup(bytes(content), "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(" ").split())


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

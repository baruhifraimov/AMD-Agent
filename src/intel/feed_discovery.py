"""Dynamic discovery of RSS feeds, blogs, and GitHub intel sources."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from src.intel.rss import is_valid_feed_url, parse_feed_entries
from src.llm import generate_cti_queries
from src.tools.cti_search import is_public_url, web_search

logger = logging.getLogger(__name__)

DEFAULT_DISCOVERY_QUERIES = [
    "Windows PE malware analysis blog rss feed",
    "malware sha256 indicators security blog feed",
    "threat intelligence rss malware research",
]

FEED_HINT_RE = re.compile(r"(feed|rss|atom|\.xml)", re.I)
GITHUB_RE = re.compile(r"^https?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+", re.I)


def classify_url(url: str) -> str:
    if GITHUB_RE.match(url):
        return "github"
    if FEED_HINT_RE.search(url) or is_valid_feed_url(url):
        return "rss_candidate"
    return "blog"


def discover_candidate_urls(
    *,
    max_sources: int = 8,
    extra_queries: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Search the public web for candidate intel source URLs."""
    queries = generate_cti_queries(
        DEFAULT_DISCOVERY_QUERIES + (extra_queries or []),
        limit=5,
    )
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    for query in queries:
        for row in web_search(query, limit=8):
            url = row.get("url", "").strip()
            if not url or url in seen or not is_public_url(url):
                continue
            seen.add(url)
            source_type = classify_url(url)
            if source_type == "github":
                candidates.append(
                    {
                        "url": url,
                        "source_type": "github",
                        "discovery_query": query,
                        "title": row.get("title", ""),
                    }
                )
            elif source_type == "blog":
                if not _looks_like_security_blog(row, url):
                    continue
                candidates.append(
                    {
                        "url": url.rstrip("/"),
                        "source_type": "blog",
                        "discovery_query": query,
                        "title": row.get("title", ""),
                    }
                )
            elif source_type == "rss_candidate" and _probe_feed(url):
                candidates.append(
                    {
                        "url": _normalize_feed_url(url, "rss"),
                        "source_type": "rss",
                        "discovery_query": query,
                        "title": row.get("title", ""),
                    }
                )
            if len(candidates) >= max_sources:
                return candidates[:max_sources]

    return candidates[:max_sources]


def _looks_like_security_blog(row: dict[str, str], url: str) -> bool:
    text = " ".join((row.get("title", ""), row.get("snippet", ""), url)).lower()
    keywords = ("malware", "threat", "security", "ransomware", "apt", "ioc", "sha256")
    return any(k in text for k in keywords)


def _probe_feed(url: str) -> bool:
    """Validate URL returns parseable feed entries."""
    if not is_valid_feed_url(url):
        return False
    entries = parse_feed_entries(url, max_entries=1)
    return len(entries) > 0


def _normalize_feed_url(url: str, source_type: str) -> str:
    if source_type == "rss" and not FEED_HINT_RE.search(url):
        parsed = urlparse(url)
        if parsed.path in ("", "/"):
            return url.rstrip("/") + "/feed/"
    return url.rstrip("/")

"""Dynamic discovery of precise RSS/Atom intel sources."""

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
    "site:thedfirreport.com feed malware sha256",
    "site:blog.talosintelligence.com rss malware sha256",
    "site:cloud.google.com/blog/topics/threat-intelligence rss malware sha256",
    "malware sha256 indicators rss feed",
]

FEED_HINT_RE = re.compile(r"(feed|rss|atom|\.xml)", re.I)
GITHUB_RE = re.compile(r"^https?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+", re.I)
LOW_SIGNAL_PATH_RE = re.compile(
    r"(manualpe|malware-detection-pe-files|static-pe-malware-analysis|"
    r"pe-structure|reverse-engineering|/abs/|/paper|/article)",
    re.I,
)
LOW_SIGNAL_CTI_HOSTS = (
    "acmrvce.com",
    "arxiv.org",
    "coursehero.com",
    "frontiersin.org",
    "github.com",
    "link.springer.com",
    "medium.com",
    "mendeley.com",
    "mdpi.com",
    "researchgate.net",
    "sciencedirect.com",
    "springer.com",
)


def is_low_signal_cti_url(url: str) -> bool:
    """Return True for hosts/pages that tend to be articles, tutorials, or papers."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if any(host == blocked or host.endswith(f".{blocked}") for blocked in LOW_SIGNAL_CTI_HOSTS):
        return True
    return bool(LOW_SIGNAL_PATH_RE.search(parsed.path or ""))


def is_precise_intel_source_url(url: str) -> bool:
    """Return True only for source URLs worth polling repeatedly.

    Repeated polling should be reserved for structured feed endpoints. One-off
    blog posts, GitHub tutorial pages, and papers are too slow and almost never
    yield downloadable PE samples.
    """
    if not is_public_url(url) or is_low_signal_cti_url(url):
        return False
    return is_valid_feed_url(url)


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
            if is_low_signal_cti_url(url):
                logger.info("Skipping low-signal CTI discovery result: %s", url)
                continue
            seen.add(url)
            source_type = classify_url(url)
            if source_type == "rss_candidate" and _probe_feed(url):
                normalized = _normalize_feed_url(url, "rss")
                if not is_precise_intel_source_url(normalized):
                    continue
                candidates.append(
                    {
                        "url": normalized,
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

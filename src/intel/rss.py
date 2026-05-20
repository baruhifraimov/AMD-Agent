"""RSS/Atom feed parsing for threat intel collection."""

from __future__ import annotations

import logging
from typing import Any
logger = logging.getLogger(__name__)


def is_valid_feed_url(url: str) -> bool:
    """Return True only when URL path strongly suggests an RSS/Atom/XML feed endpoint."""
    lower = url.lower().rstrip("/")
    if any(
        token in lower
        for token in (
            "/feed",
            "/rss",
            "/atom",
            ".xml",
            "/feeds/",
            "feed.xml",
            "rss.xml",
            "atom.xml",
        )
    ):
        return True
    return False


def parse_feed_entries(feed_url: str, *, max_entries: int = 20) -> list[dict[str, Any]]:
    """Parse feed and return normalized entry dicts."""
    try:
        import feedparser
    except ImportError as exc:
        logger.warning("feedparser unavailable: %s", exc)
        return []

    try:
        parsed = feedparser.parse(feed_url)
    except Exception as exc:
        logger.warning("Feed parse failed for %s: %s", feed_url, exc)
        return []

    if getattr(parsed, "bozo", False) and not getattr(parsed, "entries", None):
        logger.info("Feed invalid or empty: %s", feed_url)
        return []

    entries: list[dict[str, Any]] = []
    for entry in (parsed.entries or [])[:max_entries]:
        link = str(getattr(entry, "link", "") or "")
        title = str(getattr(entry, "title", "") or "")
        summary = str(getattr(entry, "summary", "") or getattr(entry, "description", "") or "")
        content_parts = []
        if hasattr(entry, "content"):
            for block in entry.content or []:
                content_parts.append(str(getattr(block, "value", "") or ""))
        body = " ".join(part for part in (summary, " ".join(content_parts)) if part)
        entries.append(
            {
                "title": title,
                "link": link,
                "body": body,
                "feed_url": feed_url,
            }
        )
    return entries

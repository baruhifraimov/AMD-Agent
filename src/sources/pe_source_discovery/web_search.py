"""Web search step for PE source discovery."""

from __future__ import annotations

import logging
from typing import Any

from src.tools.cti_search import web_search

logger = logging.getLogger(__name__)


def search_targets(targets: list[dict[str, Any]], *, max_urls: int) -> list[dict[str, str]]:
    """Run web search for planner targets; return URL + snippet rows."""
    results: list[dict[str, str]] = []
    seen: set[str] = set()

    for target in targets:
        if target.get("channel") != "web":
            continue
        for query in target.get("queries") or []:
            if len(results) >= max_urls:
                return results
            try:
                hits = web_search(str(query), limit=3)
            except Exception as exc:
                logger.warning("PE discovery search failed for %r: %s", query, exc)
                continue
            for hit in hits:
                url = str(hit.get("url") or "").strip()
                if not url or url in seen:
                    continue
                seen.add(url)
                results.append(
                    {
                        "url": url,
                        "snippet": str(hit.get("snippet") or ""),
                        "query": str(query),
                    }
                )
                if len(results) >= max_urls:
                    return results
    return results

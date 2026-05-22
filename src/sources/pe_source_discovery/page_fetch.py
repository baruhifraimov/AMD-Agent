"""Fetch page text for PE source discovery."""

from __future__ import annotations

import logging

from src.tools.cti_search import fetch_public_text

logger = logging.getLogger(__name__)


def fetch_page_text(url: str) -> str:
    try:
        return fetch_public_text(url) or ""
    except Exception as exc:
        logger.warning("PE discovery fetch failed for %s: %s", url, exc)
        return ""

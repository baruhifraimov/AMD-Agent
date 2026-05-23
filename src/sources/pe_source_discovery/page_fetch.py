"""Fetch page text for PE source discovery."""

from __future__ import annotations


from src.tools.cti_search import fetch_public_text

from src.log import PHASE_DISCOVERY, get_logger, phase_log, vlog

logger = get_logger(__name__)


def fetch_page_text(url: str) -> str:
    try:
        return fetch_public_text(url) or ""
    except Exception as exc:
        logger.warning("[%s] PE discovery fetch failed for %s: %s", PHASE_DISCOVERY, url, exc)
        return ""

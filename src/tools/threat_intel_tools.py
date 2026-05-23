"""LangChain @tool wrappers for ThreatIntelCollector."""

from __future__ import annotations

import json
from typing import Any

from src.intel.collector import ThreatIntelCollector


def _collector() -> ThreatIntelCollector:
    return ThreatIntelCollector()


def poll_intel_feeds(max_sources: int = 5, max_candidates: int = 50) -> str:
    """Poll due intel feeds and return raw IOC candidates as JSON."""
    raw = _collector().poll_due_feeds(
        max_sources=max_sources,
        max_candidates=max_candidates,
    )
    return json.dumps({"candidates": raw, "count": len(raw)})


def validate_and_queue_candidates(candidates_json: str) -> str:
    """Validate IOCs and queue PE malware hashes into the tracker DB."""
    try:
        payload = json.loads(candidates_json)
    except json.JSONDecodeError:
        payload = {"candidates": []}
    if isinstance(payload, list):
        candidates = payload
    else:
        candidates = payload.get("candidates") or []
    stats = _collector().validate_and_queue(candidates)
    return json.dumps(stats)


def build_intel_tools() -> list[Any]:
    """Return LangChain tools for Ollama binding."""
    try:
        from langchain_core.tools import tool
    except ImportError:
        return []

    @tool
    def poll_intel_feeds_tool(max_sources: int = 5, max_candidates: int = 50) -> str:
        """Poll due intel feeds for SHA256 hashes and PE URLs."""
        return poll_intel_feeds(max_sources=max_sources, max_candidates=max_candidates)

    @tool
    def validate_and_queue_candidates_tool(candidates_json: str) -> str:
        """Validate hashes (PE on MalwareBazaar) and queue pending samples."""
        return validate_and_queue_candidates(candidates_json)

    return [
        poll_intel_feeds_tool,
        validate_and_queue_candidates_tool,
    ]

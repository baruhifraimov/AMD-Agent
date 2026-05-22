"""PE dataset source discovery node — populates pe_sources registry."""

from __future__ import annotations

import logging

from src.config import pe_source_discovery_enabled
from src.sources.pe_source_discovery import run_pe_source_discovery
from src.sources.pe_source_store import PESourceStore
from src.state import AgentState

logger = logging.getLogger(__name__)


def pe_source_discovery(state: AgentState) -> dict:
    if not pe_source_discovery_enabled():
        return {"need_new_sources": False}

    need_benign = state.expected_label == 0
    stats = run_pe_source_discovery(
        need_malware=not need_benign,
        need_benign=need_benign,
    )
    metrics = dict(state.bootstrap_metrics)
    metrics["pe_source_discovery"] = stats
    logger.info(
        "PE source discovery complete: registered=%s active=%s",
        stats.get("registered"),
        stats.get("active_count"),
    )
    return {
        "bootstrap_metrics": metrics,
        "need_new_sources": False,
    }

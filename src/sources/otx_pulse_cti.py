"""OTX Pulse CTI provider — live threat intelligence via AlienVault OTX.

Fetches recent OTX pulses, extracts SHA256 indicators and raw pulse text,
routes everything through semantic_filter_hashes for LLM-based content
analysis, then validates hashes against MalwareBazaar before returning
SampleCandidate objects for download.
"""

from __future__ import annotations

from typing import Any

import src.db.tracker as db
from src.config import (
    OTX_API_KEY,
    OTX_ENABLED,
    OTX_PULSE_DAYS,
    OTX_PULSE_LIMIT,
    OTX_PULSE_MAX_HASHES,
    OTX_SKIP_SEMANTIC_FILTER_BOOTSTRAP,
    otx_enabled,
)
from src.llm import semantic_filter_hashes
from src.log import PHASE_DISCOVERY, get_logger, phase_log, task_status, vlog
from src.sources.base import PESourceProvider, SampleCandidate
from src.tools import malwarebazaar_api as mb
from src.tools.pe_download import download_pe_candidate

logger = get_logger(__name__)


class OTXPulseCTIProvider(PESourceProvider):
    name = "otx_pulse_cti"
    expected_label = 1

    def discover(
        self,
        limit: int,
        *,
        queries: list[str] | None = None,
        collection_phase: str | None = None,
    ) -> list[SampleCandidate]:
        if not otx_enabled():
            phase_log(logger, PHASE_DISCOVERY, "OTX disabled or API key not set; skipping")
            return []

        from src.tools.clients.otx_api_client import OTXApiClient

        client = OTXApiClient(OTX_API_KEY)
        with task_status(PHASE_DISCOVERY, "OTX: fetching recent pulses"):
            pulses = client.get_recent_pulses(days=OTX_PULSE_DAYS, limit=OTX_PULSE_LIMIT)
        if not pulses:
            phase_log(logger, PHASE_DISCOVERY, "OTX: no pulses returned")
            return []

        tracker = db.get_tracker()

        evidence: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()
        skipped_cached: int = 0
        max_hashes = OTX_PULSE_MAX_HASHES
        for pulse in pulses:
            if len(evidence) >= max_hashes:
                break
            raw_text = pulse.get("raw_text", "")
            for sha in pulse.get("sha256_hashes", []):
                if len(evidence) >= max_hashes:
                    break
                if sha in seen_hashes:
                    continue
                seen_hashes.add(sha)
                if tracker.get_mb_pe_verdict(sha) is False:
                    skipped_cached += 1
                    continue
                evidence.append({
                    "sha256": sha,
                    "url": "",
                    "context": raw_text[:2000],
                })

        if not evidence:
            phase_log(logger, PHASE_DISCOVERY, "OTX: no SHA256 file hash indicators in pulses")
            return []

        pe_evidence: list[dict[str, Any]] = []
        with task_status(PHASE_DISCOVERY, f"OTX: MB pre-filter on {len(evidence)} hashes"):
            for item in evidence:
                sha = str(item.get("sha256", "")).lower()
                if tracker.is_downloaded(sha) or tracker.is_corrupted(sha) or tracker.is_pending(sha):
                    continue
                try:
                    if mb.is_pe_hash(sha):
                        pe_evidence.append(item)
                except mb.MalwareBazaarUnavailable:
                    vlog(
                        logger,
                        "debug",
                        "OTX skip %s (MB unavailable during is_pe_hash)",
                        sha,
                    )
                    continue

        if skipped_cached:
            vlog(logger, "info", "OTX skipped %d hashes already cached as non-PE", skipped_cached)

        if not pe_evidence:
            phase_log(
                logger,
                PHASE_DISCOVERY,
                "otx_pulse_cti: 0 PE hashes from %d collected (%d cached non-PE)",
                len(evidence),
                skipped_cached,
            )
            return []

        if collection_phase == "bootstrap" and OTX_SKIP_SEMANTIC_FILTER_BOOTSTRAP:
            filtered = pe_evidence
        else:
            filtered = semantic_filter_hashes(pe_evidence)

        candidates: list[SampleCandidate] = []
        seen: set[str] = set()
        for item in filtered:
            if len(candidates) >= limit:
                break
            sha = str(item.get("sha256", "")).lower()
            if len(sha) != 64 or sha in seen:
                continue
            seen.add(sha)
            candidates.append(
                SampleCandidate(
                    external_id=sha,
                    provider="otx_pulse_cti",
                    expected_label=1,
                    download_ref={"sha256": sha},
                    metadata={
                        "discovery_source": "otx_pulse_cti",
                        "pulse_name": item.get("context", "")[:200],
                        "semantic_reason": item.get("semantic_reason", ""),
                        "malware_family": item.get("malware_family", ""),
                    },
                )
            )
        phase_log(
            logger,
            PHASE_DISCOVERY,
            "otx_pulse_cti: %d candidate(s) from %d PE / %d hashes / %d pulse(s)",
            len(candidates),
            len(pe_evidence),
            len(evidence),
            len(pulses),
        )
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        return download_pe_candidate(candidate)

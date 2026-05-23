"""OTX Pulse CTI provider — live threat intelligence via AlienVault OTX.

Fetches recent OTX pulses, extracts SHA256 indicators and raw pulse text,
routes everything through semantic_filter_hashes for LLM-based content
analysis, then validates hashes against MalwareBazaar before returning
SampleCandidate objects for download.
"""

from __future__ import annotations

import logging
from typing import Any

import src.db.tracker as db
from src.config import OTX_API_KEY, OTX_ENABLED, OTX_PULSE_DAYS, OTX_PULSE_LIMIT, OTX_PULSE_MAX_HASHES
from src.llm import semantic_filter_hashes
from src.sources.base import PESourceProvider, SampleCandidate
from src.tools import malwarebazaar_api as mb
from src.tools.pe_download import download_pe_candidate

logger = logging.getLogger(__name__)


class OTXPulseCTIProvider(PESourceProvider):
    name = "otx_pulse_cti"
    expected_label = 1

    def discover(
        self,
        limit: int,
        *,
        queries: list[str] | None = None,
    ) -> list[SampleCandidate]:
        if not OTX_ENABLED or not OTX_API_KEY:
            logger.info("OTX disabled or API key not set; skipping pulse discovery")
            return []

        from src.tools.clients.otx_api_client import OTXApiClient

        client = OTXApiClient(OTX_API_KEY)
        pulses = client.get_recent_pulses(days=OTX_PULSE_DAYS, limit=OTX_PULSE_LIMIT)
        if not pulses:
            return []

        evidence: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()
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
                evidence.append({
                    "sha256": sha,
                    "url": "",
                    "context": raw_text[:2000],
                })

        if not evidence:
            logger.info("OTX pulses contained no SHA256 file hash indicators")
            return []
        logger.info("OTX collected %d unique hashes (cap %d) from %d pulse(s)",
                     len(evidence), max_hashes, len(pulses))

        filtered = semantic_filter_hashes(evidence)

        tracker = db.get_tracker()
        candidates: list[SampleCandidate] = []
        seen: set[str] = set()
        for item in filtered:
            if len(candidates) >= limit:
                break
            sha = str(item.get("sha256", "")).lower()
            if len(sha) != 64 or sha in seen:
                continue
            if tracker.is_downloaded(sha) or tracker.is_corrupted(sha) or tracker.is_pending(sha):
                continue
            try:
                if not mb.is_pe_hash(sha):
                    continue
            except mb.MalwareBazaarUnavailable:
                logger.warning("MB circuit open; aborting OTX PE checks")
                break
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
        logger.info("OTX pulse discovery found %d candidate(s)", len(candidates))
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        return download_pe_candidate(candidate)

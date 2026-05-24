"""ThreatFox IOC provider — discover hashes, download via MalwareBazaar."""

from __future__ import annotations

from typing import Any

from src.config import (
    FALLBACK_PE_CHECK_MULT,
    TF_GET_IOCS_DAYS_DEFAULT,
    THREATFOX_DISCOVERY_SCAN_MULT,
)
from src.log import PHASE_DISCOVERY, get_logger, phase_log, task_status, vlog
from src.sources.base import PESourceProvider, SampleCandidate
from src.pe.profile import PE_CTI_TAGS
from src.tools import malwarebazaar_api as mb
from src.tools import threatfox_api as tf

logger = get_logger(__name__)
_WIN_PREFIXES = ("win.", "win32.", "win64.")


def _is_likely_pe(item: dict[str, Any]) -> bool:
    """True if ThreatFox IOC metadata strongly signals a Windows PE file."""
    tags = {t.lower() for t in (item.get("tags") or [])}
    if tags & PE_CTI_TAGS:
        return True
    malware = (item.get("malware") or "").lower()
    threat_type = (item.get("threat_type") or "").lower()
    return any(malware.startswith(p) for p in _WIN_PREFIXES) and threat_type == "payload"


def _accept_without_mb_check(item: dict[str, Any], *, mb_available: bool) -> bool:
    if item.get("mb_linked"):
        return True
    if mb_available:
        return False
    return _is_likely_pe(item)


class ThreatFoxProvider(PESourceProvider):
    name = "threatfox"
    expected_label = 1

    def discover(self, limit: int) -> list[SampleCandidate]:
        candidates: list[SampleCandidate] = []
        max_checks = max(limit, 1) * FALLBACK_PE_CHECK_MULT
        scan_budget = max(max_checks, 1) * THREATFOX_DISCOVERY_SCAN_MULT
        checked = 0
        with task_status(PHASE_DISCOVERY, f"ThreatFox: evaluating up to {max_checks} hashes"):
            for item in tf.get_recent_sha256_hashes(
                days=TF_GET_IOCS_DAYS_DEFAULT,
                limit=max_checks,
                scan_budget=scan_budget,
            ):
                sha = (item.get("sha256") or "").lower()
                if not sha:
                    continue
                checked += 1
                mb_up = mb.malwarebazaar_available()
                if _accept_without_mb_check(item, mb_available=mb_up):
                    vlog(
                        logger,
                        "debug",
                        "ThreatFox %s: accepted via tags/family/mb_linked (skip MB check)",
                        sha,
                    )
                elif not mb_up:
                    vlog(
                        logger,
                        "debug",
                        "ThreatFox skip %s (MB circuit open, no PE heuristic)",
                        sha,
                    )
                    continue
                else:
                    try:
                        if not mb.is_pe_hash(sha):
                            continue
                    except mb.MalwareBazaarUnavailable:
                        vlog(
                            logger,
                            "debug",
                            "ThreatFox skip %s (MB unavailable during is_pe_hash)",
                            sha,
                        )
                        continue
                    except Exception as exc:
                        vlog(logger, "debug", "ThreatFox skip %s (MB is_pe_hash): %s", sha, exc)
                        continue

                metadata = {
                    "first_seen": item.get("first_seen") or "",
                    "malware_family": item.get("malware") or "",
                    "threat_type": item.get("threat_type") or "",
                    "discovery_source": "threatfox",
                    "mb_linked": bool(item.get("mb_linked")),
                }
                download_ref: dict[str, Any] = {"sha256": sha}
                if item.get("mb_linked"):
                    download_ref["mb_linked"] = True

                candidates.append(
                    SampleCandidate(
                        external_id=sha,
                        provider=self.name,
                        expected_label=self.expected_label,
                        download_ref=download_ref,
                        metadata=metadata,
                    )
                )
                if len(candidates) >= limit:
                    break
        phase_log(
            logger,
            PHASE_DISCOVERY,
            "threatfox: %d candidate(s) retained after %d PE check(s)",
            len(candidates),
            checked,
        )
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        sha = candidate.download_ref.get("sha256") or candidate.external_id
        return mb.download_sample(sha)

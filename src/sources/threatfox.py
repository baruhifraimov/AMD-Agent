"""ThreatFox IOC provider — discover hashes, download via MalwareBazaar."""

from __future__ import annotations

from typing import Any

from src.config import FALLBACK_PE_CHECK_MULT
from src.log import PHASE_DISCOVERY, get_logger, phase_log, task_status, vlog
from src.sources.base import PESourceProvider, SampleCandidate
from src.tools import malwarebazaar_api as mb
from src.tools import threatfox_api as tf

logger = get_logger(__name__)

_PE_TAGS = frozenset({"exe", "dll", "sys", "scr", "peexe", "pedll", "pe"})
_WIN_PREFIXES = ("win.", "win32.", "win64.")


def _is_likely_pe(item: dict[str, Any]) -> bool:
    """True if ThreatFox IOC metadata strongly signals a Windows PE file."""
    tags = {t.lower() for t in (item.get("tags") or [])}
    if tags & _PE_TAGS:
        return True
    malware = (item.get("malware") or "").lower()
    threat_type = (item.get("threat_type") or "").lower()
    return any(malware.startswith(p) for p in _WIN_PREFIXES) and threat_type == "payload"


class ThreatFoxProvider(PESourceProvider):
    name = "threatfox"
    expected_label = 1

    def discover(self, limit: int) -> list[SampleCandidate]:
        candidates: list[SampleCandidate] = []
        max_checks = max(limit, 1) * FALLBACK_PE_CHECK_MULT
        checked = 0
        with task_status(PHASE_DISCOVERY, f"ThreatFox: evaluating up to {max_checks} hashes"):
            for item in tf.get_recent_sha256_hashes(days=7, limit=max_checks):
                sha = (item.get("sha256") or "").lower()
                if not sha:
                    continue
                checked += 1
                if _is_likely_pe(item):
                    vlog(logger, "debug", "ThreatFox %s: PE via tags/family, skipping MB check", sha)
                elif not mb.malwarebazaar_available():
                    logger.warning("[%s] MB circuit open; aborting ThreatFox PE checks", PHASE_DISCOVERY)
                    break
                else:
                    try:
                        if not mb.is_pe_hash(sha):
                            continue
                    except mb.MalwareBazaarUnavailable:
                        logger.warning("[%s] MB circuit open; aborting ThreatFox PE checks", PHASE_DISCOVERY)
                        break
                    except Exception as exc:
                        vlog(logger, "debug", "ThreatFox skip %s (MB is_pe_hash): %s", sha, exc)
                        continue
                candidates.append(
                    SampleCandidate(
                        external_id=sha,
                        provider=self.name,
                        expected_label=self.expected_label,
                        download_ref={"sha256": sha},
                        metadata={
                            "first_seen": item.get("first_seen") or "",
                            "malware_family": item.get("malware") or "",
                            "threat_type": item.get("threat_type") or "",
                            "discovery_source": "threatfox",
                        },
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

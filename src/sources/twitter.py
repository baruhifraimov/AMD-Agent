"""Twitter/X CTI provider — social IOCs via ThreatFox reference filtering."""

from __future__ import annotations

from src.config import FALLBACK_PE_CHECK_MULT
from src.log import PHASE_DISCOVERY, get_logger, phase_log, task_status, vlog
from src.sources.base import PESourceProvider, SampleCandidate
from src.tools import malwarebazaar_api as mb
from src.tools import threatfox_api as tf

logger = get_logger(__name__)


class TwitterProvider(PESourceProvider):
    name = "twitter"
    expected_label = 1

    def discover(self, limit: int) -> list[SampleCandidate]:
        candidates: list[SampleCandidate] = []
        max_checks = max(limit, 1) * FALLBACK_PE_CHECK_MULT
        checked = 0
        with task_status(PHASE_DISCOVERY, f"Twitter CTI: evaluating up to {max_checks} hashes"):
            for item in tf.get_social_sha256_hashes(days=7, limit=max_checks):
                sha = (item.get("sha256") or "").lower()
                if not sha:
                    continue
                checked += 1
                if not mb.malwarebazaar_available():
                    logger.warning("[%s] MB circuit open; aborting Twitter CTI PE checks", PHASE_DISCOVERY)
                    break
                try:
                    if not mb.is_pe_hash(sha):
                        continue
                except mb.MalwareBazaarUnavailable:
                    logger.warning("[%s] MB circuit open; aborting Twitter CTI PE checks", PHASE_DISCOVERY)
                    break
                except Exception as exc:
                    vlog(logger, "debug", "Twitter CTI skip %s (MB is_pe_hash): %s", sha, exc)
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
                            "discovery_source": "twitter_cti",
                            "reference": item.get("reference") or "",
                        },
                    )
                )
                if len(candidates) >= limit:
                    break
        phase_log(
            logger,
            PHASE_DISCOVERY,
            "twitter: %d candidate(s) retained after %d PE check(s)",
            len(candidates),
            checked,
        )
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        sha = candidate.download_ref.get("sha256") or candidate.external_id
        return mb.download_sample(sha)

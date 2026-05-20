"""Twitter/X CTI provider — social IOCs via ThreatFox reference filtering."""

from __future__ import annotations

import logging

from src.sources.base import PESourceProvider, SampleCandidate
from src.tools import malwarebazaar as mb
from src.tools import threatfox as tf

logger = logging.getLogger(__name__)


class TwitterProvider(PESourceProvider):
    name = "twitter"
    expected_label = 1

    def discover(self, limit: int) -> list[SampleCandidate]:
        candidates: list[SampleCandidate] = []
        for item in tf.get_social_sha256_hashes(days=7, limit=limit * 3):
            sha = (item.get("sha256") or "").lower()
            if not sha:
                continue
            try:
                if not mb.is_pe_hash(sha):
                    continue
            except Exception as exc:
                logger.debug("Twitter CTI skip %s (MB is_pe_hash): %s", sha, exc)
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
        logger.info("Twitter CTI discover found %d candidate(s)", len(candidates))
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        sha = candidate.download_ref.get("sha256") or candidate.external_id
        return mb.download_sample(sha)

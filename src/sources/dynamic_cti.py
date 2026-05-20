"""Dynamic CTI hash discovery provider.

Uses ThreatIntelCollector.web_discover for unified CTI logic.
Binary download uses MalwareBazaar primary with controlled URL fallbacks
via download_pe_candidate (see src/tools/pe_download.py).
"""

from __future__ import annotations

import logging

from src.sources.base import PESourceProvider, SampleCandidate
from src.tools.pe_download import download_pe_candidate

logger = logging.getLogger(__name__)


class DynamicCTIProvider(PESourceProvider):
    name = "dynamic_cti"
    expected_label = 1

    def discover(
        self,
        limit: int,
        *,
        queries: list[str] | None = None,
    ) -> list[SampleCandidate]:
        from src.intel.collector import ThreatIntelCollector

        return ThreatIntelCollector().web_discover(limit, queries=queries)

    def download(self, candidate: SampleCandidate) -> bytes:
        return download_pe_candidate(candidate)

"""Dynamic CTI hash discovery provider.

Hybrid Strict policy: web pages are used only to discover malware hashes and
semantic evidence. Binary download still happens through a provider-controlled
path (MalwareBazaar hash lookup/download), never arbitrary CTI URLs.
"""

from __future__ import annotations

import logging

from src.config import CTI_PAGE_LIMIT
from src.llm import generate_cti_queries, semantic_filter_hashes
from src.sources.base import PESourceProvider, SampleCandidate
from src.tools import malwarebazaar as mb
from src.tools.cti_search import extract_hash_contexts, fetch_public_text, web_search

logger = logging.getLogger(__name__)

DEFAULT_QUERIES = [
    "recent Windows PE malware sha256 hashes github",
    "recent malware campaign sha256 PE hashes",
    "Windows executable malware SHA256 indicators",
]


class DynamicCTIProvider(PESourceProvider):
    name = "dynamic_cti"
    expected_label = 1

    def discover(self, limit: int) -> list[SampleCandidate]:
        queries = generate_cti_queries(DEFAULT_QUERIES, limit=3)
        evidence: list[dict] = []
        visited: set[str] = set()

        for query in queries:
            for result in web_search(query):
                if len(visited) >= CTI_PAGE_LIMIT:
                    break
                url = result["url"]
                if url in visited:
                    continue
                visited.add(url)
                page_text = fetch_public_text(url)
                combined = " ".join(
                    part
                    for part in (result.get("title", ""), result.get("snippet", ""), page_text)
                    if part
                )
                evidence.extend(extract_hash_contexts(combined, url=url))
            if len(visited) >= CTI_PAGE_LIMIT:
                break

        accepted = semantic_filter_hashes(evidence)
        candidates: list[SampleCandidate] = []
        seen: set[str] = set()
        for item in accepted:
            if len(candidates) >= limit:
                break
            sha = str(item.get("sha256", "")).lower()
            if sha in seen or len(sha) != 64:
                continue
            seen.add(sha)
            try:
                if not mb.is_pe_hash(sha):
                    continue
            except Exception as exc:
                logger.info("Skipping CTI hash not confirmed by MalwareBazaar %s: %s", sha, exc)
                continue
            candidates.append(
                SampleCandidate(
                    external_id=sha,
                    provider=self.name,
                    expected_label=self.expected_label,
                    download_ref={"sha256": sha},
                    metadata={
                        "discovery_source": "dynamic_cti",
                        "origin_url": item.get("url", ""),
                        "semantic_evidence": item.get("context", "")[:1000],
                        "semantic_reason": item.get("semantic_reason", ""),
                    },
                )
            )

        logger.info("Dynamic CTI discovered %d candidate(s)", len(candidates))
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        sha = candidate.download_ref.get("sha256") or candidate.external_id
        return mb.download_sample(sha)

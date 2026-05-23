"""Sysinternals live directory benign PE provider."""

from __future__ import annotations

import random
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from src.config import SYSINTERNALS_BASE_URLS
from src.sources.base import PESourceProvider, SampleCandidate

from src.log import PHASE_DISCOVERY, get_logger, phase_log, vlog

logger = get_logger(__name__)

_EXE_PATTERN = re.compile(r"\.exe$", re.IGNORECASE)


class SysinternalsProvider(PESourceProvider):
    name = "sysinternals"
    expected_label = 0

    def discover(self, limit: int) -> list[SampleCandidate]:
        links = self._collect_exe_links()
        if not links:
            return []
        random.shuffle(links)
        selected = links[:limit]
        return [
            SampleCandidate(
                external_id=url,
                provider=self.name,
                expected_label=self.expected_label,
                download_ref={"url": url},
                metadata={"file_name": urlparse(url).path.split("/")[-1]},
            )
            for url in selected
        ]

    def download(self, candidate: SampleCandidate) -> bytes:
        url = candidate.download_ref.get("url") or candidate.external_id
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.content

    def _collect_exe_links(self) -> list[str]:
        found: set[str] = set()
        for base_url in SYSINTERNALS_BASE_URLS:
            try:
                with httpx.Client(timeout=60.0, follow_redirects=True) as client:
                    response = client.get(base_url)
                    response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                for anchor in soup.find_all("a", href=True):
                    href = anchor["href"].strip()
                    if not href or href.startswith("?"):
                        continue
                    full = urljoin(base_url, href)
                    if _EXE_PATTERN.search(urlparse(full).path):
                        found.add(full)
            except Exception as exc:
                logger.warning("[%s] Sysinternals listing failed for %s: %s", PHASE_DISCOVERY, base_url, exc)
        return sorted(found)

"""MalShare PE malware source provider."""

from __future__ import annotations

from src.config import malshare_enabled
from src.sources.base import PESourceProvider, SampleCandidate
from src.tools.clients.malshare_api_client import MalShareClient, MalShareUnavailable


class MalShareProvider(PESourceProvider):
    name = "malshare"
    expected_label = 1

    def discover(self, limit: int) -> list[SampleCandidate]:
        if not malshare_enabled():
            return []
        try:
            client = MalShareClient.from_config()
        except (MalShareUnavailable, ValueError):
            return []

        candidates: list[SampleCandidate] = []
        for row in client.list_pe32_hashes(limit=limit):
            h = str(row.get("hash") or row.get("md5") or row.get("sha256") or "").lower()
            if not h:
                continue
            sha = h if len(h) == 64 else ""
            candidates.append(
                SampleCandidate(
                    external_id=sha or h,
                    provider=self.name,
                    expected_label=self.expected_label,
                    download_ref={"hash": h, "sha256": sha},
                    metadata={"source": "malshare", "malshare_row": row},
                )
            )
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        client = MalShareClient.from_config()
        h = str(
            candidate.download_ref.get("hash")
            or candidate.download_ref.get("sha256")
            or candidate.external_id
        )
        return client.download(h)

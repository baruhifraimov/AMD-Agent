"""GitHub Releases API benign PE provider."""

from __future__ import annotations

import io
import zipfile
from typing import Any

import httpx

from src.config import GITHUB_API_URL, GITHUB_BENIGN_REPOS, get_github_token
from src.sources.base import PESourceProvider, SampleCandidate

from src.log import PHASE_DISCOVERY, get_logger, phase_log, vlog

logger = get_logger(__name__)

DISCOVERABLE_ASSET_SUFFIXES = (".exe", ".zip")
PE_ARCHIVE_SUFFIXES = (".exe", ".dll", ".sys", ".scr")


class GitHubReleasesProvider(PESourceProvider):
    name = "github"
    expected_label = 0

    def discover(self, limit: int) -> list[SampleCandidate]:
        candidates: list[SampleCandidate] = []
        for owner, repo in GITHUB_BENIGN_REPOS:
            if len(candidates) >= limit:
                break
            try:
                assets = self._list_release_assets(owner, repo)
            except Exception as exc:
                logger.warning("[%s] GitHub discover failed %s/%s: %s", PHASE_DISCOVERY, owner, repo, exc)
                continue
            for asset in assets:
                if len(candidates) >= limit:
                    break
                url = asset.get("browser_download_url", "")
                name = asset.get("name", "")
                if not url:
                    continue
                lower = name.lower()
                if not lower.endswith(DISCOVERABLE_ASSET_SUFFIXES):
                    vlog(logger, "debug", "Skipping non-PE asset: %s", name)
                    continue
                candidates.append(
                    SampleCandidate(
                        external_id=url,
                        provider=self.name,
                        expected_label=self.expected_label,
                        download_ref={
                            "url": url,
                            "name": name,
                            "owner": owner,
                            "repo": repo,
                        },
                        metadata={
                            "file_name": name,
                            "owner": owner,
                            "repo": repo,
                        },
                    )
                )
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        url = candidate.download_ref.get("url") or candidate.external_id
        name = (candidate.download_ref.get("name") or "").lower()
        headers = self._headers()
        with httpx.Client(timeout=180.0, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            data = response.content
        if name.endswith(".zip"):
            return self._extract_first_pe_from_zip(data)
        return data

    def _headers(self) -> dict[str, str]:
        token = get_github_token()
        if token:
            return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        return {"Accept": "application/vnd.github+json"}

    def _list_release_assets(self, owner: str, repo: str) -> list[dict[str, Any]]:
        url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/releases/latest"
        with httpx.Client(timeout=60.0) as client:
            response = client.get(url, headers=self._headers())
            if response.status_code == 404:
                return []
            response.raise_for_status()
            payload = response.json()
        return payload.get("assets") or []

    @staticmethod
    def _extract_first_pe_from_zip(data: bytes) -> bytes:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.lower().endswith(PE_ARCHIVE_SUFFIXES):
                    return zf.read(name)
        raise RuntimeError("No PE file found inside GitHub release zip")

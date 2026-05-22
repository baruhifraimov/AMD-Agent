"""Benign-NET GitHub repo benign PE provider."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from src.config import BENIGN_NET_MAX_DISCOVER, BENIGN_NET_REPO_URL, REPOS_DIR, ensure_dirs
from src.sources.base import PESourceProvider, SampleCandidate

logger = logging.getLogger(__name__)

_REPO_NAME = "benign-net"


class BenignNetProvider(PESourceProvider):
    name = "benign_net"
    expected_label = 0

    def _repo_dir(self) -> Path:
        ensure_dirs()
        REPOS_DIR.mkdir(parents=True, exist_ok=True)
        return REPOS_DIR / _REPO_NAME

    def _ensure_repo(self) -> Path:
        dest = self._repo_dir()
        if not (dest / ".git").exists():
            logger.info("Cloning Benign-NET into %s", dest)
            subprocess.check_call(
                ["git", "clone", "--depth", "1", BENIGN_NET_REPO_URL, str(dest)],
                timeout=600,
            )
        else:
            try:
                subprocess.check_call(
                    ["git", "-C", str(dest), "pull", "--ff-only"],
                    timeout=300,
                )
            except subprocess.CalledProcessError as exc:
                logger.warning("Benign-NET git pull failed: %s", exc)
        return dest

    def discover(self, limit: int) -> list[SampleCandidate]:
        cap = min(limit, BENIGN_NET_MAX_DISCOVER)
        try:
            root = self._ensure_repo()
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Benign-NET repo unavailable: %s", exc)
            return []

        candidates: list[SampleCandidate] = []
        for path in root.rglob("*.exe"):
            if not path.is_file():
                continue
            candidates.append(
                SampleCandidate(
                    external_id=str(path.resolve()),
                    provider=self.name,
                    expected_label=self.expected_label,
                    download_ref={"path": str(path.resolve())},
                    metadata={"source": "benign_net", "file_name": path.name},
                )
            )
            if len(candidates) >= cap:
                break
        return candidates

    def download(self, candidate: SampleCandidate) -> bytes:
        path = Path(
            str(candidate.download_ref.get("path") or candidate.external_id)
        )
        if not path.is_file():
            raise FileNotFoundError(f"Benign-NET file missing: {path}")
        return path.read_bytes()

"""Benign-NET GitHub repo benign PE provider."""

from __future__ import annotations

import random
import subprocess
import time
from pathlib import Path

from src.config import BENIGN_NET_REPO_URL, REPOS_DIR, ensure_dirs
from src.sources.base import PESourceProvider, SampleCandidate

from src.log import PHASE_DISCOVERY, get_logger, phase_log, vlog

logger = get_logger(__name__)

_REPO_NAME = "benign-net"
_PULL_INTERVAL_SECS = 7 * 24 * 3600  # cache fresh ~1 week — skip pull otherwise


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
            phase_log(logger, PHASE_DISCOVERY, "Cloning Benign-NET into %s", dest)
            subprocess.check_call(
                ["git", "clone", "--depth", "1", BENIGN_NET_REPO_URL, str(dest)],
                timeout=300,
            )
            return dest
        fetch_head = dest / ".git" / "FETCH_HEAD"
        if fetch_head.exists() and (time.time() - fetch_head.stat().st_mtime) < _PULL_INTERVAL_SECS:
            return dest  # cached copy still fresh — skip network
        try:
            subprocess.check_call(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                timeout=120,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.warning("[%s] Benign-NET pull failed; using cached copy: %s", PHASE_DISCOVERY, exc)
        return dest

    def discover(self, limit: int) -> list[SampleCandidate]:
        try:
            root = self._ensure_repo()
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("[%s] Benign-NET repo unavailable: %s", PHASE_DISCOVERY, exc)
            return []

        paths = [p for p in root.rglob("*.exe") if p.is_file()]
        random.shuffle(paths)
        return [
            SampleCandidate(
                external_id=str(path.resolve()),
                provider=self.name,
                expected_label=self.expected_label,
                download_ref={"path": str(path.resolve())},
                metadata={"source": "benign_net", "file_name": path.name},
            )
            for path in paths[:limit]
        ]

    def download(self, candidate: SampleCandidate) -> bytes:
        path = Path(
            str(candidate.download_ref.get("path") or candidate.external_id)
        )
        if not path.is_file():
            raise FileNotFoundError(f"Benign-NET file missing: {path}")
        return path.read_bytes()

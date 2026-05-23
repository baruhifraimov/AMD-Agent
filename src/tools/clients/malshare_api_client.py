"""MalShare API client."""

from __future__ import annotations

import logging
from typing import Any

from src.config import get_malshare_api_key, malshare_enabled
from src.tools.clients.http_client_base import ApiUnavailable, HttpApiClient

logger = logging.getLogger(__name__)

MALSHARE_API_URL = "https://malshare.com/api.php"


class MalShareUnavailable(ApiUnavailable):
    """Raised when MalShare is disabled or unavailable."""


class MalShareClient(HttpApiClient):
    """MalShare public malware repository API."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or get_malshare_api_key()
        super().__init__(
            base_url=MALSHARE_API_URL,
            min_request_interval=1.0,
        )

    @classmethod
    def from_config(cls) -> MalShareClient:
        if not malshare_enabled():
            raise MalShareUnavailable("MalShare is disabled (set MALSHARE_ENABLED=True in src/config.py)")
        return cls()

    def _params(self, extra: dict[str, str]) -> dict[str, str]:
        return {"api_key": self._api_key, **extra}

    def get_limit(self) -> dict[str, Any]:
        response = self.get(self._params({"action": "getlimit"}), timeout=30.0)
        try:
            return response.json()
        except Exception:
            return {"raw": response.text}

    def list_pe32_hashes(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent PE32 hashes from the last 24h."""
        response = self.get(
            self._params({"action": "type", "type": "PE32"}),
            timeout=30.0,
        )
        try:
            data = response.json()
        except Exception as exc:
            logger.warning("MalShare list PE32 parse failed: %s", exc)
            return []

        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            rows = data.get("samples") or data.get("data") or []
        else:
            return []

        results: list[dict[str, Any]] = []
        for row in rows[:limit]:
            if isinstance(row, str):
                h = row.strip().lower()
                if h:
                    results.append({"hash": h, "md5": h if len(h) == 32 else ""})
                continue
            if not isinstance(row, dict):
                continue
            h = (
                row.get("sha256")
                or row.get("md5")
                or row.get("hash")
                or row.get("SHA256")
                or row.get("MD5")
                or ""
            )
            h = str(h).strip().lower()
            if h:
                results.append(dict(row, hash=h))
        return results[:limit]

    def download(self, file_hash: str) -> bytes:
        h = file_hash.strip().lower()
        response = self.get(
            self._params({"action": "getfile", "hash": h}),
            timeout=120.0,
        )
        return response.content

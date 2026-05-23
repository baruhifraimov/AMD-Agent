"""AlienVault OTX API client for threat pulse discovery."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from src.tools.clients.http_client_base import CircuitBreaker, HttpApiClient

from src.log import PHASE_API, get_logger, phase_log, vlog

logger = get_logger(__name__)

OTX_API_BASE = "https://otx.alienvault.com/api/v1/"
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class OTXApiClient(HttpApiClient):
    """AlienVault OTX pulse discovery client."""

    def __init__(self, api_key: str) -> None:
        super().__init__(
            base_url=OTX_API_BASE,
            headers={"X-OTX-API-KEY": api_key},
            min_request_interval=1.0,
            circuit=CircuitBreaker(
                failure_threshold=3,
                open_seconds=120.0,
                open_seconds_429=3600.0,
            ),
        )
        self._api_key = api_key

    def get_recent_pulses(
        self,
        *,
        days: int = 30,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        since = datetime.now(timezone.utc) - timedelta(days=max(1, days))
        modified_since = since.strftime("%Y-%m-%dT%H:%M:%S")

        try:
            response = self.get(
                {"modified_since": modified_since, "limit": min(limit, 50)},
                endpoint="pulses/subscribed",
                timeout=30.0,
            )
            payload = response.json()
        except Exception as exc:
            logger.warning("[%s] OTX pulse fetch failed: %s", PHASE_API, exc)
            return []

        results_list = payload.get("results") or []
        pulses: list[dict[str, Any]] = []

        for pulse in results_list:
            if not isinstance(pulse, dict):
                continue
            pulse_id = str(pulse.get("id") or "")
            name = str(pulse.get("name") or "")
            description = str(pulse.get("description") or "")
            tags = pulse.get("tags") or []
            if isinstance(tags, list):
                tags = [str(t) for t in tags]
            else:
                tags = []
            references = pulse.get("references") or []
            if isinstance(references, list):
                references = [str(r) for r in references]
            else:
                references = []

            sha256_hashes: list[str] = []
            indicator_context_parts: list[str] = []
            for indicator in pulse.get("indicators") or []:
                if not isinstance(indicator, dict):
                    continue
                ioc_type = str(indicator.get("type") or "").lower()
                ioc_value = str(indicator.get("indicator") or "").strip().lower()
                if ioc_type in ("filehash-sha256", "sha256") and SHA256_RE.fullmatch(ioc_value):
                    sha256_hashes.append(ioc_value)
                ind_title = str(indicator.get("title") or "")
                ind_desc = str(indicator.get("description") or "")
                if ind_title or ind_desc:
                    indicator_context_parts.append(f"{ind_title} {ind_desc}".strip())

            raw_text = " ".join(
                part for part in [
                    name,
                    description,
                    " ".join(tags),
                    " ".join(references),
                    " ".join(indicator_context_parts),
                ] if part
            )

            pulses.append({
                "pulse_id": pulse_id,
                "pulse_name": name,
                "description": description,
                "tags": tags,
                "sha256_hashes": sha256_hashes,
                "raw_text": raw_text,
            })
            if len(pulses) >= limit:
                break

        vlog(logger, "info", "OTX fetched %d pulse(s) with %d total hashes",
                     len(pulses), sum(len(p["sha256_hashes"]) for p in pulses))
        return pulses

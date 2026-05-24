"""ThreatFox API client (abuse.ch)."""

from __future__ import annotations

import re
from typing import Any

import httpx

import src.config as app_config
from src.config import get_auth_key
from src.tools.clients.http_client_base import ApiUnavailable, CircuitBreaker, HttpApiClient

from src.log import get_logger, vlog
from src.pe.profile import PE_CTI_TAGS

logger = get_logger(__name__)

THREATFOX_API_URL = app_config.THREATFOX_API_URL
SHA256_IOC_TYPES = frozenset({"sha256_hash", "hash", "file_hash", "sha256"})
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SOCIAL_REFERENCE_RE = re.compile(r"(?:twitter\.com|x\.com)", re.I)
_BAZAAR_LINK_RE = re.compile(r"bazaar\.abuse\.ch", re.I)
_BACKOFF_SECONDS = (10.0, 30.0, 60.0)


class ThreatFoxClient(HttpApiClient):
    """ThreatFox IOC discovery client."""

    def __init__(self) -> None:
        circuit = CircuitBreaker(
            failure_threshold=app_config.TF_CIRCUIT_FAILURE_THRESHOLD,
            open_seconds=app_config.TF_CIRCUIT_OPEN_SECONDS,
            open_seconds_429=app_config.TF_CIRCUIT_OPEN_SECONDS_429,
        )
        super().__init__(
            base_url=app_config.THREATFOX_API_URL,
            headers=self._build_headers(),
            min_request_interval=app_config.TF_MIN_REQUEST_INTERVAL,
            circuit=circuit,
            backoff_seconds=_BACKOFF_SECONDS,
            http2=False,
        )

    @classmethod
    def from_config(cls) -> ThreatFoxClient:
        return cls()

    @staticmethod
    def _build_headers() -> dict[str, str]:
        return {
            "Auth-Key": get_auth_key(),
            "User-Agent": app_config.TF_USER_AGENT,
        }

    def _post_json(self, payload: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        effective_timeout = timeout if timeout is not None else app_config.TF_GET_IOCS_TIMEOUT
        response = self.post_form(payload, timeout=effective_timeout, use_json=True)
        return self._parse_json_response(response)

    def _post_json_quick(self, payload: dict[str, Any], *, timeout: float = 45.0) -> dict[str, Any]:
        """Single-attempt POST for bulky get_iocs (taginfo fallback follows)."""
        self._circuit.ensure_available()
        self._limiter.wait()
        try:
            with httpx.Client(timeout=timeout, http2=False) as client:
                response = client.post(
                    self.base_url,
                    json=payload,
                    headers=self.headers,
                )
            if response.status_code == 429:
                raise ApiUnavailable("Rate limited (HTTP 429)")
            response.raise_for_status()
            return self._parse_json_response(response)
        except Exception:
            # Optional bulk get_iocs; taginfo fallback covers discovery — do not open circuit.
            raise

    @staticmethod
    def _parse_json_response(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise httpx.DecodingError(f"ThreatFox JSON decode failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise httpx.DecodingError("ThreatFox response is not a JSON object")
        return payload

    @staticmethod
    def _extract_sha256(row: dict[str, Any]) -> str | None:
        entries = ThreatFoxClient._iter_sha256_entries(row)
        return entries[0][0] if entries else None

    @staticmethod
    def _iter_sha256_entries(row: dict[str, Any]) -> list[tuple[str, bool]]:
        """Return (sha256, mb_linked) tuples from a ThreatFox IOC row."""
        results: list[tuple[str, bool]] = []
        seen: set[str] = set()

        def add(sha: str, mb_linked: bool) -> None:
            normalized = sha.strip().lower()
            if not SHA256_RE.fullmatch(normalized) or normalized in seen:
                return
            seen.add(normalized)
            results.append((normalized, mb_linked))

        ioc_type = (row.get("ioc_type") or "").lower()
        ioc = str(row.get("ioc") or "").strip().lower()
        if ioc_type in SHA256_IOC_TYPES and SHA256_RE.fullmatch(ioc):
            add(ioc, False)
        elif SHA256_RE.fullmatch(ioc):
            add(ioc, False)

        nested = row.get("malware_sample") or row.get("malware_samples")
        if isinstance(nested, dict):
            nested = [nested]
        if isinstance(nested, list):
            for item in nested:
                if not isinstance(item, dict):
                    continue
                sha = (item.get("sha256_hash") or item.get("sha256") or "").lower()
                bazaar_ref = str(item.get("malware_bazaar") or "")
                mb_linked = bool(bazaar_ref and _BAZAAR_LINK_RE.search(bazaar_ref))
                add(sha, mb_linked)

        return results

    @staticmethod
    def _row_priority(row: dict[str, Any], *, mb_linked: bool) -> int:
        score = 100
        ioc_type = (row.get("ioc_type") or "").lower()
        if ioc_type in SHA256_IOC_TYPES:
            score -= 40
        if mb_linked:
            score -= 30
        tags = {str(t).lower() for t in (row.get("tags") or []) if isinstance(t, str)}
        if tags & PE_CTI_TAGS:
            score -= 20
        return score

    @staticmethod
    def _entry_from_row(
        row: dict[str, Any],
        sha: str,
        *,
        mb_linked: bool,
    ) -> dict[str, Any]:
        return {
            "sha256": sha,
            "malware": row.get("malware_printable") or row.get("malware") or "",
            "first_seen": row.get("first_seen") or "",
            "threat_type": row.get("threat_type") or "",
            "tags": [str(t) for t in (row.get("tags") or []) if isinstance(t, str)],
            "mb_linked": mb_linked,
            "_priority": ThreatFoxClient._row_priority(row, mb_linked=mb_linked),
        }

    def _collect_sha256_hashes(
        self,
        payload: dict[str, Any],
        *,
        limit: int,
        scan_budget: int,
        social_only: bool = False,
    ) -> list[dict[str, Any]]:
        if payload.get("query_status") != "ok":
            label = "get_iocs (social)" if social_only else "get_iocs"
            vlog(logger, "warning", "ThreatFox %s status=%s", label, payload.get("query_status"))
            return []

        pending: list[dict[str, Any]] = []
        seen: set[str] = set()
        examined = 0

        for row in payload.get("data") or []:
            if examined >= scan_budget:
                break
            if not isinstance(row, dict):
                continue
            if social_only and not self._is_social_reference(row):
                continue

            for sha, mb_linked in self._iter_sha256_entries(row):
                examined += 1
                if sha in seen:
                    continue
                seen.add(sha)
                entry = self._entry_from_row(row, sha, mb_linked=mb_linked)
                if social_only:
                    entry["reference"] = str(row.get("reference") or "")
                pending.append(entry)
                if examined >= scan_budget:
                    break

        pending.sort(key=lambda item: (item.pop("_priority", 100), item.get("first_seen") or ""))
        return pending[:limit]

    def _fetch_get_iocs_payload(self, days: int) -> dict[str, Any] | None:
        """Try get_iocs once; return None if the response cannot be fetched or parsed."""
        attempt_days = max(1, min(int(days), 7))
        try:
            payload = self._post_json_quick({"query": "get_iocs", "days": attempt_days})
        except (httpx.TransportError, httpx.DecodingError, ApiUnavailable) as exc:
            vlog(
                logger,
                "warning",
                "ThreatFox get_iocs days=%s failed: %s",
                attempt_days,
                exc,
            )
            return None
        if payload.get("query_status") == "ok":
            return payload
        vlog(
            logger,
            "warning",
            "ThreatFox get_iocs days=%s status=%s",
            attempt_days,
            payload.get("query_status"),
        )
        return None

    def _discover_via_taginfo(
        self,
        *,
        limit: int,
        scan_budget: int,
    ) -> list[dict[str, Any]]:
        """Paginated tag queries when get_iocs is too large or unstable."""
        pending: list[dict[str, Any]] = []
        seen: set[str] = set()
        examined = 0
        tag_limit = min(app_config.THREATFOX_TAGINFO_LIMIT, max(scan_budget, limit))

        for tag in app_config.THREATFOX_TAG_QUERIES:
            if examined >= scan_budget and len(pending) >= limit:
                break
            try:
                payload = self._post_json(
                    {"query": "taginfo", "tag": tag, "limit": tag_limit},
                    timeout=60.0,
                )
            except (httpx.TransportError, ApiUnavailable) as exc:
                vlog(logger, "warning", "ThreatFox taginfo tag=%s failed: %s", tag, exc)
                continue
            if payload.get("query_status") != "ok":
                continue
            for row in payload.get("data") or []:
                if examined >= scan_budget:
                    break
                if not isinstance(row, dict):
                    continue
                for sha, mb_linked in self._iter_sha256_entries(row):
                    examined += 1
                    if sha in seen:
                        continue
                    seen.add(sha)
                    pending.append(self._entry_from_row(row, sha, mb_linked=mb_linked))
                if examined >= scan_budget:
                    break

        pending.sort(key=lambda item: (item.pop("_priority", 100), item.get("first_seen") or ""))
        vlog(
            logger,
            "info",
            "ThreatFox taginfo fallback: %d hash(es) from %d examined",
            min(len(pending), limit),
            examined,
        )
        return pending[:limit]

    def get_recent_sha256_hashes(
        self,
        *,
        days: int | None = None,
        limit: int = 10,
        scan_budget: int | None = None,
    ) -> list[dict[str, Any]]:
        effective_days = app_config.TF_GET_IOCS_DAYS_DEFAULT if days is None else days
        effective_days = max(1, min(int(effective_days), 7))
        effective_scan = scan_budget if scan_budget is not None else limit
        effective_scan = max(int(effective_scan), limit)

        payload = self._fetch_get_iocs_payload(effective_days)
        if payload is not None:
            rows = self._collect_sha256_hashes(
                payload,
                limit=limit,
                scan_budget=effective_scan,
                social_only=False,
            )
            if rows:
                return rows

        return self._discover_via_taginfo(limit=limit, scan_budget=effective_scan)

    @staticmethod
    def _is_social_reference(row: dict[str, Any]) -> bool:
        reference = str(row.get("reference") or "")
        return bool(SOCIAL_REFERENCE_RE.search(reference))

    def get_social_sha256_hashes(
        self,
        *,
        days: int | None = None,
        limit: int = 10,
        scan_budget: int | None = None,
    ) -> list[dict[str, Any]]:
        effective_days = app_config.TF_GET_IOCS_DAYS_DEFAULT if days is None else days
        effective_days = max(1, min(int(effective_days), 7))
        effective_scan = scan_budget if scan_budget is not None else limit
        effective_scan = max(int(effective_scan), limit)

        payload = self._post_json({"query": "get_iocs", "days": effective_days})
        return self._collect_sha256_hashes(
            payload,
            limit=limit,
            scan_budget=effective_scan,
            social_only=True,
        )

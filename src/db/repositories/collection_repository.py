"""Provider yield and candidate tracking repository."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src import config
from src.db.database import DatabaseManager
from src.db.row_utils import parse_utc, utc_now_iso


class CollectionRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def increment_collection_counter(self, name: str) -> int:
        now = utc_now_iso()
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO collection_counters (name, value, updated_at)
                VALUES (?, 1, ?)
                ON CONFLICT(name) DO UPDATE SET
                    value = value + 1,
                    updated_at = excluded.updated_at
                """,
                (name, now),
            )
            row = conn.execute(
                "SELECT value FROM collection_counters WHERE name = ?",
                (name,),
            ).fetchone()
        return int(row["value"]) if row else 1
    def is_provider_cooled_down(self, provider: str, label: int | None) -> bool:
        needed = config.PROVIDER_COOLDOWN_ZERO_RUNS
        label_sql = "label IS NULL" if label is None else "label = ?"
        params: tuple[Any, ...] = (provider, needed) if label is None else (provider, label, needed)
        with self._db.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM provider_runs
                WHERE provider = ? AND {label_sql}
                ORDER BY id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        if len(rows) < needed:
            return False
        last = parse_utc(str(rows[0]["created_at"]))
        if last is None:
            return False
        age = (datetime.now(timezone.utc) - last).total_seconds()
        if age > config.PROVIDER_COOLDOWN_SECONDS:
            return False
        for row in rows:
            activity = max(
                int(row["requested"] or 0),
                int(row["discovered"] or 0),
                int(row["returned"] or 0),
                int(row["download_attempted"] or 0),
            )
            if activity < config.PROVIDER_COOLDOWN_MIN_ATTEMPTS:
                return False
            if int(row["feature_extracted"] or 0) > 0:
                return False
        return True
    def provider_recent_stats(
        self,
        provider: str,
        label: int | None,
        *,
        window: int = 10,
    ) -> dict[str, int]:
        label_sql = "label IS NULL" if label is None else "label = ?"
        params: tuple[Any, ...] = (provider, window) if label is None else (provider, label, window)
        with self._db.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM provider_runs
                WHERE provider = ? AND {label_sql}
                ORDER BY id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        keys = (
            "requested",
            "discovered",
            "fresh",
            "returned",
            "download_attempted",
            "downloaded",
            "duplicate",
            "non_pe",
            "valid_pe",
            "feature_extracted",
            "failed",
        )
        out = {key: 0 for key in keys}
        out["runs"] = len(rows)
        for row in rows:
            for key in keys:
                out[key] += int(row[key] or 0)
        return out
    def provider_success_rate(self, provider: str, label: int | None, *, window: int = 10) -> float | None:
        stats = self.provider_recent_stats(provider, label, window=window)
        if stats["runs"] == 0:
            return None
        attempts = max(
            int(stats.get("download_attempted", 0)),
            int(stats.get("returned", 0)),
            int(stats.get("discovered", 0)),
        )
        if attempts <= 0:
            return 0.0
        return float(stats.get("feature_extracted", 0)) / float(attempts)
    def rank_providers_by_yield(self, providers: list[str], label: int) -> list[str]:
        indexed = list(dict.fromkeys(providers))

        def score(name: str) -> tuple[int, float, int]:
            cooled = self.is_provider_cooled_down(name, label)
            rate = self.provider_success_rate(name, label)
            return (1 if cooled else 0, -(0.5 if rate is None else rate), indexed.index(name))

        return sorted(indexed, key=score)
    def record_candidate_outcome(
        self,
        candidate_key: str,
        *,
        status: str,
        error: str | None = None,
        sha256: str | None = None,
        increment_attempts: bool = False,
    ) -> None:
        if not candidate_key:
            return
        now = utc_now_iso()
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO candidates
                (candidate_key, provider, status, attempts, first_seen_at, last_seen_at, last_error, sha256)
                VALUES (?, 'unknown', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(candidate_key) DO UPDATE SET
                    status = excluded.status,
                    attempts = candidates.attempts + ?,
                    last_seen_at = excluded.last_seen_at,
                    last_error = excluded.last_error,
                    sha256 = COALESCE(NULLIF(excluded.sha256, ''), candidates.sha256)
                """,
                (
                    candidate_key,
                    status,
                    1 if increment_attempts else 0,
                    now,
                    now,
                    error,
                    sha256 or "",
                    1 if increment_attempts else 0,
                ),
            )
    def record_candidate_seen(
        self,
        *,
        candidate_key: str,
        provider: str,
        label: int | None,
        external_id: str = "",
        sha256: str = "",
        source_url: str = "",
        status: str = "seen",
    ) -> None:
        if not candidate_key or not provider:
            return
        now = utc_now_iso()
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO candidates
                (candidate_key, provider, label, external_id, sha256, source_url, status,
                 attempts, first_seen_at, last_seen_at, last_error)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)
                ON CONFLICT(candidate_key) DO UPDATE SET
                    provider = excluded.provider,
                    label = excluded.label,
                    external_id = COALESCE(NULLIF(excluded.external_id, ''), candidates.external_id),
                    sha256 = COALESCE(NULLIF(excluded.sha256, ''), candidates.sha256),
                    source_url = COALESCE(NULLIF(excluded.source_url, ''), candidates.source_url),
                    status = excluded.status,
                    last_seen_at = excluded.last_seen_at
                """,
                (
                    candidate_key,
                    provider,
                    label,
                    external_id,
                    sha256,
                    source_url,
                    status,
                    now,
                    now,
                ),
            )
    def record_provider_run(
        self,
        *,
        provider: str,
        label: int | None,
        phase: str = "",
        stage: str = "",
        requested: int = 0,
        discovered: int = 0,
        fresh: int = 0,
        returned: int = 0,
        download_attempted: int = 0,
        downloaded: int = 0,
        duplicate: int = 0,
        non_pe: int = 0,
        valid_pe: int = 0,
        feature_extracted: int = 0,
        failed: int = 0,
    ) -> None:
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_runs
                (provider, label, phase, stage, requested, discovered, fresh, returned,
                 download_attempted, downloaded, duplicate, non_pe, valid_pe,
                 feature_extracted, failed, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider,
                    label,
                    phase,
                    stage,
                    requested,
                    discovered,
                    fresh,
                    returned,
                    download_attempted,
                    downloaded,
                    duplicate,
                    non_pe,
                    valid_pe,
                    feature_extracted,
                    failed,
                    utc_now_iso(),
                ),
            )

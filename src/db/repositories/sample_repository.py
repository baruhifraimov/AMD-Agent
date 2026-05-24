"""Sample lifecycle and provenance repository."""

from __future__ import annotations

import json
from typing import Any

from src.config import FEATURE_DIM, FEATURE_SET_VERSION
from src.db.database import DatabaseManager
from src.db.row_utils import row_to_dict, utc_now_iso


class SampleRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def count_by_label(self) -> dict[int, int]:
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT label, COUNT(*) as cnt FROM samples
                WHERE label IS NOT NULL
                  AND features_json IS NOT NULL
                  AND feature_version = ?
                  AND feature_dim = ?
                  AND file_path IS NOT NULL
                  AND file_path != ''
                  AND COALESCE(status, 'active') = 'active'
                GROUP BY label
                """,
                (FEATURE_SET_VERSION, FEATURE_DIM),
            ).fetchall()
        return {int(r["label"]): int(r["cnt"]) for r in rows}
    def fetch_chronological(self) -> list[dict[str, Any]]:
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM samples ORDER BY COALESCE(NULLIF(ingested_at, ''), acquired_at) ASC"
            ).fetchall()
        return [row_to_dict(r) for r in rows]
    def fetch_pending_hashes(self, limit: int = 10) -> list[dict[str, Any]]:
        """Hashes not yet downloaded (oldest first)."""
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT sha256, acquired_at FROM samples
                WHERE (file_path IS NULL OR file_path = '')
                  AND label = 1
                  AND COALESCE(status, 'pending') IN ('pending', 'active')
                ORDER BY acquired_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {"sha256": str(r["sha256"]).lower(), "acquired_at": r["acquired_at"]}
            for r in rows
        ]
    def get_sample(self, sha256: str) -> dict[str, Any] | None:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM samples WHERE sha256 = ?",
                (sha256.lower(),),
            ).fetchone()
        if row is None:
            return None
        return row_to_dict(row)
    def hash_exists(self, sha256: str) -> bool:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM samples WHERE sha256 = ?", (sha256.lower(),)
            ).fetchone()
        return row is not None
    def insert_pending_hash(
        self,
        sha256: str,
        acquired_at: str | None = None,
        *,
        label: int = 1,
        source_first_seen: str | None = None,
    ) -> None:
        """Insert a malware hash awaiting download (no overwrite if exists)."""
        ingested = utc_now_iso()
        acquired = acquired_at or ingested
        source_seen = source_first_seen or acquired_at
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO samples
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status, ingested_at, source_first_seen)
                VALUES (?, '', ?, NULL, ?, NULL, NULL, 'pending', ?, ?)
                """,
                (sha256.lower(), acquired, label, ingested, source_seen),
            )
    def insert_sample(
        self,
        sha256: str,
        file_path: str,
        acquired_at: str,
        *,
        features: dict[str, Any] | None = None,
        label: int | None = 1,
        prediction: float | None = None,
        anomaly_score: float | None = None,
        status: str = "active",
        reject_reason: str | None = None,
        rejected_at: str | None = None,
        source_provider: str | None = None,
        source_url: str | None = None,
        ingested_at: str | None = None,
        source_first_seen: str | None = None,
    ) -> None:
        features_json = json.dumps(features) if features is not None else None
        feature_version = FEATURE_SET_VERSION if features is not None else None
        feature_dim = FEATURE_DIM if features is not None else None
        ingested = ingested_at or acquired_at or utc_now_iso()
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO samples
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status, reject_reason, rejected_at, source_provider, source_url, feature_version, feature_dim, ingested_at, source_first_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256.lower(),
                    file_path,
                    acquired_at,
                    features_json,
                    label,
                    prediction,
                    anomaly_score,
                    status,
                    reject_reason,
                    rejected_at,
                    source_provider,
                    source_url,
                    feature_version,
                    feature_dim,
                    ingested,
                    source_first_seen,
                ),
            )
            if source_url:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO sample_sources
                    (source_url, sha256, source_provider, first_seen_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (source_url, sha256.lower(), source_provider, acquired_at),
                )
    def is_corrupted(self, sha256: str) -> bool:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM samples WHERE sha256 = ? AND status = 'corrupted'",
                (sha256.lower(),),
            ).fetchone()
        return row is not None
    def is_downloaded(self, sha256: str) -> bool:
        """True when sample exists and has a non-empty file_path on disk."""
        with self._db.connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM samples
                WHERE sha256 = ?
                  AND file_path IS NOT NULL
                  AND file_path != ''
                  AND COALESCE(status, 'active') != 'corrupted'
                """,
                (sha256.lower(),),
            ).fetchone()
        return row is not None
    def is_pending(self, sha256: str) -> bool:
        """True when row exists but file_path is empty (pending malware queue)."""
        with self._db.connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM samples
                WHERE sha256 = ?
                  AND (file_path IS NULL OR file_path = '')
                  AND COALESCE(status, 'pending') IN ('pending', 'active')
                """,
                (sha256.lower(),),
            ).fetchone()
        return row is not None
    def is_source_url_seen(self, url: str) -> bool:
        normalized = url.strip()
        if not normalized:
            return False
        with self._db.connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM samples
                WHERE source_url = ?
                  AND COALESCE(status, 'active') != 'corrupted'
                """,
                (normalized,),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    """
                    SELECT 1 FROM sample_sources ss
                    JOIN samples s ON s.sha256 = ss.sha256
                    WHERE ss.source_url = ?
                      AND COALESCE(s.status, 'active') != 'corrupted'
                    """,
                    (normalized,),
                ).fetchone()
        return row is not None
    def mark_corrupted(
        self,
        sha256: str,
        reason: str,
        *,
        file_path: str | None = None,
        acquired_at: str | None = None,
        label: int | None = 1,
        source_first_seen: str | None = None,
    ) -> None:
        """Mark a sample as rejected/corrupted so pending queues do not reprocess it."""
        sha = sha256.lower()
        ingested = utc_now_iso()
        acquired = acquired_at or ingested
        rejected_at = utc_now_iso()
        with self._db.connect() as conn:
            row = conn.execute("SELECT 1 FROM samples WHERE sha256 = ?", (sha,)).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO samples
                    (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status, reject_reason, rejected_at, ingested_at, source_first_seen)
                    VALUES (?, ?, ?, NULL, ?, NULL, NULL, 'corrupted', ?, ?, ?, ?)
                    """,
                    (
                        sha,
                        file_path or "",
                        acquired,
                        label,
                        reason,
                        rejected_at,
                        ingested,
                        source_first_seen or acquired_at,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE samples
                    SET status = 'corrupted',
                        reject_reason = ?,
                        rejected_at = ?,
                        ingested_at = COALESCE(NULLIF(ingested_at, ''), ?),
                        source_first_seen = COALESCE(NULLIF(source_first_seen, ''), ?),
                        file_path = CASE
                            WHEN ? IS NOT NULL AND ? != '' THEN ?
                            ELSE file_path
                        END
                    WHERE sha256 = ?
                    """,
                    (
                        reason,
                        rejected_at,
                        ingested,
                        source_first_seen or acquired_at,
                        file_path,
                        file_path,
                        file_path,
                        sha,
                    ),
                )
    def record_sample_source(
        self,
        sha256: str,
        *,
        source_provider: str | None = None,
        source_url: str | None = None,
    ) -> None:
        normalized = (source_url or "").strip()
        if not normalized:
            return
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO sample_sources
                (source_url, sha256, source_provider, first_seen_at)
                VALUES (?, ?, ?, ?)
                """,
                (normalized, sha256.lower(), source_provider, utc_now_iso()),
            )
            conn.execute(
                """
                UPDATE samples
                SET source_provider = COALESCE(source_provider, ?),
                    source_url = COALESCE(NULLIF(source_url, ''), ?)
                WHERE sha256 = ?
                """,
                (source_provider, normalized, sha256.lower()),
            )
    def update_file_path(
        self,
        sha256: str,
        file_path: str,
        *,
        source_provider: str | None = None,
        source_url: str | None = None,
        ingested_at: str | None = None,
        source_first_seen: str | None = None,
    ) -> None:
        """Set sandbox path after download for a pending row."""
        ingested = ingested_at or utc_now_iso()
        with self._db.connect() as conn:
            conn.execute(
                """
                UPDATE samples
                SET file_path = ?,
                    status = 'active',
                    reject_reason = NULL,
                    rejected_at = NULL,
                    source_provider = COALESCE(NULLIF(source_provider, ''), ?),
                    source_url = COALESCE(NULLIF(source_url, ''), ?),
                    ingested_at = COALESCE(NULLIF(ingested_at, ''), ?),
                    source_first_seen = COALESCE(NULLIF(source_first_seen, ''), ?)
                WHERE sha256 = ?
                """,
                (
                    file_path,
                    source_provider,
                    source_url,
                    ingested,
                    source_first_seen,
                    sha256.lower(),
                ),
            )
            if source_url:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO sample_sources
                    (source_url, sha256, source_provider, first_seen_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (source_url, sha256.lower(), source_provider, ingested),
                )

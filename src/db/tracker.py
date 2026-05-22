"""SQLite tracker for processed malware samples."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from src import config
from src.config import DB_PATH, FEATURE_DIM, FEATURE_SET_VERSION, ensure_dirs

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256 TEXT PRIMARY KEY,
    file_path TEXT,
    acquired_at TEXT NOT NULL,
    features_json TEXT,
    label INTEGER,
    prediction REAL,
    anomaly_score REAL,
    status TEXT NOT NULL DEFAULT 'active',
    reject_reason TEXT,
    rejected_at TEXT,
    source_provider TEXT,
    source_url TEXT,
    feature_version TEXT,
    feature_dim INTEGER
);
CREATE INDEX IF NOT EXISTS idx_samples_acquired ON samples(acquired_at);
CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status);
CREATE INDEX IF NOT EXISTS idx_samples_source_url ON samples(source_url);
CREATE INDEX IF NOT EXISTS idx_samples_feature_version ON samples(feature_version);
CREATE TABLE IF NOT EXISTS mb_hash_cache (
    sha256 TEXT PRIMARY KEY,
    is_pe INTEGER NOT NULL,
    cached_at TEXT NOT NULL,
    query_status TEXT
);
CREATE TABLE IF NOT EXISTS mb_api_usage (
    usage_date TEXT PRIMARY KEY,
    get_file_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sample_sources (
    source_url TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    source_provider TEXT,
    first_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sample_sources_sha256 ON sample_sources(sha256);
"""


def get_tracker(db_path: Path | None = None) -> "MalwareTracker":
    """Factory using current config DB_PATH."""
    return MalwareTracker(db_path or DB_PATH)


class MalwareTracker:
    """Persistent store for PE samples and features."""

    def __init__(self, db_path: Path | None = None) -> None:
        ensure_dirs()
        self.db_path = Path(db_path) if db_path else Path(DB_PATH)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA journal_mode=WAL;")
            self._migrate_schema(conn)

    @staticmethod
    def _migrate_schema(conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(samples)")}
        if "status" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN status TEXT")
        if "reject_reason" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN reject_reason TEXT")
        if "rejected_at" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN rejected_at TEXT")
        if "source_provider" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN source_provider TEXT")
        if "source_url" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN source_url TEXT")
        if "feature_version" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN feature_version TEXT")
        if "feature_dim" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN feature_dim INTEGER")
        conn.execute(
            """
            UPDATE samples
            SET status = CASE
                WHEN file_path IS NULL OR file_path = '' THEN 'pending'
                ELSE 'active'
            END
            WHERE status IS NULL OR status = ''
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_source_url ON samples(source_url)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_feature_version ON samples(feature_version)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sample_sources (
                source_url TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                source_provider TEXT,
                first_seen_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sample_sources_sha256 ON sample_sources(sha256)")
        conn.execute(
            """
            INSERT OR IGNORE INTO sample_sources
            (source_url, sha256, source_provider, first_seen_at)
            SELECT source_url, sha256, source_provider, acquired_at
            FROM samples
            WHERE source_url IS NOT NULL AND source_url != ''
            """
        )

    def hash_exists(self, sha256: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM samples WHERE sha256 = ?", (sha256.lower(),)
            ).fetchone()
        return row is not None

    def is_downloaded(self, sha256: str) -> bool:
        """True when sample exists and has a non-empty file_path on disk."""
        with self._connect() as conn:
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
        """True when row exists but file_path is empty (ThreatIngestor queue)."""
        with self._connect() as conn:
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

    def is_corrupted(self, sha256: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM samples WHERE sha256 = ? AND status = 'corrupted'",
                (sha256.lower(),),
            ).fetchone()
        return row is not None

    def is_source_url_seen(self, url: str) -> bool:
        normalized = url.strip()
        if not normalized:
            return False
        with self._connect() as conn:
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
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO sample_sources
                (source_url, sha256, source_provider, first_seen_at)
                VALUES (?, ?, ?, ?)
                """,
                (normalized, sha256.lower(), source_provider, self.utc_now_iso()),
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

    def fetch_pending_hashes(self, limit: int = 10) -> list[dict[str, Any]]:
        """Hashes from ThreatIngestor not yet downloaded (oldest first)."""
        with self._connect() as conn:
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

    def insert_pending_hash(
        self,
        sha256: str,
        acquired_at: str | None = None,
        *,
        label: int = 1,
    ) -> None:
        """Insert a ThreatIngestor hash awaiting download (no overwrite if exists)."""
        acquired = acquired_at or self.utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO samples
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status)
                VALUES (?, '', ?, NULL, ?, NULL, NULL, 'pending')
                """,
                (sha256.lower(), acquired, label),
            )

    def update_file_path(self, sha256: str, file_path: str) -> None:
        """Set sandbox path after download for a pending row."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE samples
                SET file_path = ?, status = 'active', reject_reason = NULL, rejected_at = NULL
                WHERE sha256 = ?
                """,
                (file_path, sha256.lower()),
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
    ) -> None:
        features_json = json.dumps(features) if features is not None else None
        feature_version = FEATURE_SET_VERSION if features is not None else None
        feature_dim = FEATURE_DIM if features is not None else None
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO samples
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status, reject_reason, rejected_at, source_provider, source_url, feature_version, feature_dim)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    def mark_corrupted(
        self,
        sha256: str,
        reason: str,
        *,
        file_path: str | None = None,
        acquired_at: str | None = None,
        label: int | None = 1,
    ) -> None:
        """Mark a sample as rejected/corrupted so pending queues do not reprocess it."""
        sha = sha256.lower()
        acquired = acquired_at or self.utc_now_iso()
        rejected_at = self.utc_now_iso()
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM samples WHERE sha256 = ?", (sha,)).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO samples
                    (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status, reject_reason, rejected_at)
                    VALUES (?, ?, ?, NULL, ?, NULL, NULL, 'corrupted', ?, ?)
                    """,
                    (sha, file_path or "", acquired, label, reason, rejected_at),
                )
            else:
                conn.execute(
                    """
                    UPDATE samples
                    SET status = 'corrupted',
                        reject_reason = ?,
                        rejected_at = ?,
                        file_path = CASE
                            WHEN ? IS NOT NULL AND ? != '' THEN ?
                            ELSE file_path
                        END
                    WHERE sha256 = ?
                    """,
                    (reason, rejected_at, file_path, file_path, file_path, sha),
                )

    def update_features(self, sha256: str, features: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE samples
                SET features_json = ?,
                    feature_version = ?,
                    feature_dim = ?
                WHERE sha256 = ?
                """,
                (json.dumps(features), FEATURE_SET_VERSION, FEATURE_DIM, sha256.lower()),
            )

    def update_prediction(self, sha256: str, prediction: float) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE samples SET prediction = ? WHERE sha256 = ?",
                (prediction, sha256.lower()),
            )

    def update_anomaly_score(self, sha256: str, score: float) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE samples SET anomaly_score = ? WHERE sha256 = ?",
                (score, sha256.lower()),
            )

    def get_sample(self, sha256: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM samples WHERE sha256 = ?",
                (sha256.lower(),),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def fetch_chronological(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM samples ORDER BY acquired_at ASC"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def fetch_labeled_with_features(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM samples
                WHERE features_json IS NOT NULL
                  AND label IS NOT NULL
                  AND file_path IS NOT NULL
                  AND file_path != ''
                  AND COALESCE(status, 'active') = 'active'
                ORDER BY acquired_at ASC
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_by_label(self) -> dict[int, int]:
        with self._connect() as conn:
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

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if d.get("features_json"):
            d["features"] = json.loads(d["features_json"])
        return d

    @staticmethod
    def utc_now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def utc_today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def get_mb_pe_verdict(self, sha256: str) -> bool | None:
        """Return cached PE verdict, or None on miss or expired entry."""
        key = sha256.lower()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT is_pe, cached_at FROM mb_hash_cache WHERE sha256 = ?",
                (key,),
            ).fetchone()
        if not row:
            return None
        cached_at = row["cached_at"]
        try:
            cached_dt = datetime.strptime(cached_at, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None
        age_days = (datetime.now(timezone.utc) - cached_dt).total_seconds() / 86400
        if age_days > config.MB_INFO_CACHE_TTL_DAYS:
            return None
        return bool(row["is_pe"])

    def set_mb_pe_verdict(
        self,
        sha256: str,
        is_pe: bool,
        *,
        query_status: str = "ok",
    ) -> None:
        key = sha256.lower()
        now = self.utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO mb_hash_cache (sha256, is_pe, cached_at, query_status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    is_pe = excluded.is_pe,
                    cached_at = excluded.cached_at,
                    query_status = excluded.query_status
                """,
                (key, int(is_pe), now, query_status),
            )

    def _mb_download_count(self, conn: sqlite3.Connection, day: str) -> int:
        conn.execute(
            """
            INSERT INTO mb_api_usage (usage_date, get_file_count)
            VALUES (?, 0)
            ON CONFLICT(usage_date) DO NOTHING
            """,
            (day,),
        )
        row = conn.execute(
            "SELECT get_file_count FROM mb_api_usage WHERE usage_date = ?",
            (day,),
        ).fetchone()
        return int(row["get_file_count"]) if row else 0

    def mb_download_quota_available(self, *, limit: int | None = None) -> bool:
        """Return True if another get_file download is allowed today."""
        cap = limit if limit is not None else config.MB_DAILY_DOWNLOAD_LIMIT
        day = self.utc_today()
        with self._connect() as conn:
            count = self._mb_download_count(conn, day)
        return count < cap

    def record_mb_download(self) -> bool:
        """Increment daily get_file counter after a successful download."""
        cap = config.MB_DAILY_DOWNLOAD_LIMIT
        day = self.utc_today()
        with self._connect() as conn:
            self._mb_download_count(conn, day)
            conn.execute(
                """
                UPDATE mb_api_usage
                SET get_file_count = get_file_count + 1
                WHERE usage_date = ? AND get_file_count < ?
                """,
                (day, cap),
            )
            updated = conn.execute("SELECT changes()").fetchone()
        return bool(updated and int(updated[0]) > 0)

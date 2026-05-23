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
    feature_dim INTEGER,
    ingested_at TEXT,
    source_first_seen TEXT,
    malware_family TEXT,
    task_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_samples_acquired ON samples(acquired_at);
CREATE INDEX IF NOT EXISTS idx_samples_ingested ON samples(ingested_at);
CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status);
CREATE INDEX IF NOT EXISTS idx_samples_source_url ON samples(source_url);
CREATE INDEX IF NOT EXISTS idx_samples_feature_version ON samples(feature_version);
CREATE INDEX IF NOT EXISTS idx_samples_family ON samples(malware_family);
CREATE INDEX IF NOT EXISTS idx_samples_task_id ON samples(task_id);
CREATE TABLE IF NOT EXISTS task_log (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    trigger TEXT,
    replay_budget_used INTEGER,
    model_version TEXT
);
CREATE TABLE IF NOT EXISTS family_counts (
    malware_family TEXT PRIMARY KEY,
    sample_count INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT
);
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
CREATE TABLE IF NOT EXISTS provider_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    label INTEGER,
    phase TEXT,
    stage TEXT,
    requested INTEGER NOT NULL DEFAULT 0,
    discovered INTEGER NOT NULL DEFAULT 0,
    fresh INTEGER NOT NULL DEFAULT 0,
    returned INTEGER NOT NULL DEFAULT 0,
    download_attempted INTEGER NOT NULL DEFAULT 0,
    downloaded INTEGER NOT NULL DEFAULT 0,
    duplicate INTEGER NOT NULL DEFAULT 0,
    non_pe INTEGER NOT NULL DEFAULT 0,
    valid_pe INTEGER NOT NULL DEFAULT 0,
    feature_extracted INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_runs_provider_label ON provider_runs(provider, label, created_at);
CREATE TABLE IF NOT EXISTS candidates (
    candidate_key TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    label INTEGER,
    external_id TEXT,
    sha256 TEXT,
    source_url TEXT,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_candidates_provider ON candidates(provider, label, status);
CREATE INDEX IF NOT EXISTS idx_candidates_sha256 ON candidates(sha256);
CREATE TABLE IF NOT EXISTS collection_counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
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
        if "ingested_at" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN ingested_at TEXT")
        if "source_first_seen" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN source_first_seen TEXT")
        if "malware_family" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN malware_family TEXT")
        if "task_id" not in columns:
            conn.execute("ALTER TABLE samples ADD COLUMN task_id INTEGER")
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_ingested ON samples(ingested_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_family ON samples(malware_family)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_task_id ON samples(task_id)")
        conn.execute(
            """
            UPDATE samples
            SET ingested_at = acquired_at
            WHERE ingested_at IS NULL OR ingested_at = ''
            """
        )
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
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS provider_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                label INTEGER,
                phase TEXT,
                stage TEXT,
                requested INTEGER NOT NULL DEFAULT 0,
                discovered INTEGER NOT NULL DEFAULT 0,
                fresh INTEGER NOT NULL DEFAULT 0,
                returned INTEGER NOT NULL DEFAULT 0,
                download_attempted INTEGER NOT NULL DEFAULT 0,
                downloaded INTEGER NOT NULL DEFAULT 0,
                duplicate INTEGER NOT NULL DEFAULT 0,
                non_pe INTEGER NOT NULL DEFAULT 0,
                valid_pe INTEGER NOT NULL DEFAULT 0,
                feature_extracted INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_provider_runs_provider_label
                ON provider_runs(provider, label, created_at);
            CREATE TABLE IF NOT EXISTS candidates (
                candidate_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                label INTEGER,
                external_id TEXT,
                sha256 TEXT,
                source_url TEXT,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_candidates_provider ON candidates(provider, label, status);
            CREATE INDEX IF NOT EXISTS idx_candidates_sha256 ON candidates(sha256);
            CREATE TABLE IF NOT EXISTS collection_counters (
                name TEXT PRIMARY KEY,
                value INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_log (
                task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                sample_count INTEGER NOT NULL DEFAULT 0,
                trigger TEXT,
                replay_budget_used INTEGER,
                model_version TEXT
            );
            CREATE TABLE IF NOT EXISTS family_counts (
                malware_family TEXT PRIMARY KEY,
                sample_count INTEGER NOT NULL DEFAULT 0,
                last_seen_at TEXT
            );
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
        """True when row exists but file_path is empty (pending malware queue)."""
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
        """Hashes not yet downloaded (oldest first)."""
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
        source_first_seen: str | None = None,
    ) -> None:
        """Insert a malware hash awaiting download (no overwrite if exists)."""
        ingested = self.utc_now_iso()
        acquired = acquired_at or ingested
        source_seen = source_first_seen or acquired_at
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO samples
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status, ingested_at, source_first_seen)
                VALUES (?, '', ?, NULL, ?, NULL, NULL, 'pending', ?, ?)
                """,
                (sha256.lower(), acquired, label, ingested, source_seen),
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
        ingested = ingested_at or self.utc_now_iso()
        with self._connect() as conn:
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
        ingested = ingested_at or acquired_at or self.utc_now_iso()
        with self._connect() as conn:
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
        ingested = self.utc_now_iso()
        acquired = acquired_at or ingested
        rejected_at = self.utc_now_iso()
        with self._connect() as conn:
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
                "SELECT * FROM samples ORDER BY COALESCE(NULLIF(ingested_at, ''), acquired_at) ASC"
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
                ORDER BY COALESCE(NULLIF(ingested_at, ''), acquired_at) ASC
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_family(self, sha256: str, family: str) -> None:
        """Update malware family and family counts."""
        sha = sha256.lower()
        fam = (family or "unknown").strip().lower()
        now = self.utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE samples SET malware_family = ? WHERE sha256 = ?",
                (fam, sha),
            )
            conn.execute(
                """
                INSERT INTO family_counts (malware_family, sample_count, last_seen_at)
                VALUES (?, 1, ?)
                ON CONFLICT(malware_family) DO UPDATE SET
                    sample_count = sample_count + 1,
                    last_seen_at = excluded.last_seen_at
                """,
                (fam, now),
            )

    def fetch_labeled_with_features_and_family(self) -> list[dict[str, Any]]:
        return self.fetch_labeled_with_features()

    def get_family_counts(self) -> dict[str, int]:
        """Return counts of active samples per family."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT malware_family, COUNT(*) as cnt FROM samples
                WHERE label = 1
                  AND features_json IS NOT NULL
                  AND file_path IS NOT NULL
                  AND file_path != ''
                  AND COALESCE(status, 'active') = 'active'
                  AND malware_family IS NOT NULL
                GROUP BY malware_family
                """
            ).fetchall()
        return {str(r["malware_family"]): int(r["cnt"]) for r in rows}

    def get_current_task_id(self) -> int:
        """Return the highest task_id, or 0 if none exist."""
        with self._connect() as conn:
            row = conn.execute("SELECT MAX(task_id) as max_id FROM task_log").fetchone()
        return int(row["max_id"]) if row and row["max_id"] is not None else 0

    def create_task(self, trigger: str, sample_count: int) -> int:
        """Create a new chronological task and return its ID."""
        now = self.utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO task_log (created_at, sample_count, trigger)
                VALUES (?, ?, ?)
                """,
                (now, sample_count, trigger),
            )
            return cursor.lastrowid or 0

    def update_sample_task(self, sha256: str, task_id: int) -> None:
        """Assign a sample to a task ID."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE samples SET task_id = ? WHERE sha256 = ?",
                (task_id, sha256.lower()),
            )

    def get_all_task_ids(self) -> list[int]:
        """Return list of all task IDs ordered by creation time."""
        with self._connect() as conn:
            rows = conn.execute("SELECT task_id FROM task_log ORDER BY task_id ASC").fetchall()
        return [int(r["task_id"]) for r in rows]

    def fetch_task_holdout(self, task_id: int) -> list[dict[str, Any]]:
        """Fetch valid labeled features belonging to a specific task."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM samples
                WHERE task_id = ?
                  AND features_json IS NOT NULL
                  AND label IS NOT NULL
                  AND file_path IS NOT NULL
                  AND file_path != ''
                  AND COALESCE(status, 'active') = 'active'
                """,
                (task_id,),
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
        with self._connect() as conn:
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
                    self.utc_now_iso(),
                ),
            )

    def provider_recent_stats(
        self,
        provider: str,
        label: int | None,
        *,
        window: int = 10,
    ) -> dict[str, int]:
        label_sql = "label IS NULL" if label is None else "label = ?"
        params: tuple[Any, ...] = (provider, window) if label is None else (provider, label, window)
        with self._connect() as conn:
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

    def is_provider_cooled_down(self, provider: str, label: int | None) -> bool:
        needed = config.PROVIDER_COOLDOWN_ZERO_RUNS
        label_sql = "label IS NULL" if label is None else "label = ?"
        params: tuple[Any, ...] = (provider, needed) if label is None else (provider, label, needed)
        with self._connect() as conn:
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
        last = self._parse_utc(str(rows[0]["created_at"]))
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

    def rank_providers_by_yield(self, providers: list[str], label: int) -> list[str]:
        indexed = list(dict.fromkeys(providers))

        def score(name: str) -> tuple[int, float, int]:
            cooled = self.is_provider_cooled_down(name, label)
            rate = self.provider_success_rate(name, label)
            return (1 if cooled else 0, -(0.5 if rate is None else rate), indexed.index(name))

        return sorted(indexed, key=score)

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
        now = self.utc_now_iso()
        with self._connect() as conn:
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
        now = self.utc_now_iso()
        with self._connect() as conn:
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

    def increment_collection_counter(self, name: str) -> int:
        now = self.utc_now_iso()
        with self._connect() as conn:
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

    def temporal_split_health(
        self,
        *,
        train_ratio: float = 0.7,
        val_ratio: float = 0.15,
    ) -> dict[str, Any]:
        rows = self.fetch_labeled_with_features()
        labels = [int(row["label"]) for row in rows if row.get("label") in (0, 1)]
        n = len(labels)
        if n < 5:
            return {"healthy": False, "support": n, "reason": "insufficient"}
        train_end = int(n * train_ratio)
        val_end = int(n * (train_ratio + val_ratio))
        splits = {
            "train": labels[:train_end],
            "val": labels[train_end:val_end],
            "test": labels[val_end:],
        }
        out: dict[str, Any] = {"support": n}
        healthy = True
        for name, values in splits.items():
            counts = {0: values.count(0), 1: values.count(1)}
            out[f"{name}_benign"] = counts[0]
            out[f"{name}_malware"] = counts[1]
            if counts[0] == 0 or counts[1] == 0:
                healthy = False
        out["healthy"] = healthy
        if not healthy:
            out["reason"] = "single_class_split"
        return out

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if d.get("features_json"):
            d["features"] = json.loads(d["features_json"])
        return d

    @staticmethod
    def _parse_utc(value: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

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

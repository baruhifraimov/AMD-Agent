"""SQLite tracker for processed malware samples."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from src.config import DB_PATH, ensure_dirs

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
    rejected_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_acquired ON samples(acquired_at);
CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status);
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
    ) -> None:
        features_json = json.dumps(features) if features is not None else None
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO samples
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score, status, reject_reason, rejected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
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
                "UPDATE samples SET features_json = ? WHERE sha256 = ?",
                (json.dumps(features), sha256.lower()),
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
                  AND file_path IS NOT NULL
                  AND file_path != ''
                  AND COALESCE(status, 'active') = 'active'
                GROUP BY label
                """
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

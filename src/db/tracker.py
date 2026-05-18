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
    anomaly_score REAL
);
CREATE INDEX IF NOT EXISTS idx_samples_acquired ON samples(acquired_at);
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
                """,
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
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score)
                VALUES (?, '', ?, NULL, ?, NULL, NULL)
                """,
                (sha256.lower(), acquired, label),
            )

    def update_file_path(self, sha256: str, file_path: str) -> None:
        """Set sandbox path after download for a pending row."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE samples SET file_path = ? WHERE sha256 = ?",
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
    ) -> None:
        features_json = json.dumps(features) if features is not None else None
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO samples
                (sha256, file_path, acquired_at, features_json, label, prediction, anomaly_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256.lower(),
                    file_path,
                    acquired_at,
                    features_json,
                    label,
                    prediction,
                    anomaly_score,
                ),
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
                WHERE features_json IS NOT NULL AND label IS NOT NULL
                ORDER BY acquired_at ASC
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_by_label(self) -> dict[int, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT label, COUNT(*) as cnt FROM samples WHERE label IS NOT NULL GROUP BY label"
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

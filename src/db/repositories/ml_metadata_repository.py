"""ML feature and training-state repository."""

from __future__ import annotations

import json
from typing import Any

from src.config import FEATURE_DIM, FEATURE_SET_VERSION
from src.db.database import DatabaseManager
from src.db.row_utils import row_to_dict, utc_now_iso


class MLMetadataRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def count_untrained_with_features(self) -> int:
        """Count active labeled samples with features that have never been trained on."""
        with self._db.connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) as cnt FROM samples
                WHERE trained_at IS NULL
                  AND features_json IS NOT NULL
                  AND status = 'active'
                  AND label IS NOT NULL
                  AND file_path IS NOT NULL
                  AND file_path != ''
                """
            ).fetchone()
        return int(row["cnt"]) if row else 0
    def fetch_labeled_with_features(self) -> list[dict[str, Any]]:
        with self._db.connect() as conn:
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
        return [row_to_dict(r) for r in rows]
    def fetch_labeled_with_features_and_family(self) -> list[dict[str, Any]]:
        return self.fetch_labeled_with_features()
    def fetch_untrained_with_features(self) -> list[dict[str, Any]]:
        """Fetch active labeled samples with features that have never been trained on."""
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM samples
                WHERE trained_at IS NULL
                  AND features_json IS NOT NULL
                  AND status = 'active'
                  AND label IS NOT NULL
                  AND file_path IS NOT NULL
                  AND file_path != ''
                ORDER BY COALESCE(NULLIF(ingested_at, ''), acquired_at) ASC
                """
            ).fetchall()
        return [row_to_dict(r) for r in rows]
    def mark_all_trained(self, task_id: int | None = None) -> int:
        """Mark all active labeled featured samples as trained. Returns count updated."""
        now = utc_now_iso()
        with self._db.connect() as conn:
            conn.execute(
                """
                UPDATE samples SET trained_at = ?
                WHERE trained_at IS NULL
                  AND features_json IS NOT NULL
                  AND status = 'active'
                  AND label IS NOT NULL
                  AND file_path IS NOT NULL
                  AND file_path != ''
                """,
                (now,),
            )
            row = conn.execute("SELECT changes() as cnt").fetchone()
        return int(row["cnt"]) if row else 0
    def update_anomaly_score(self, sha256: str, score: float) -> None:
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE samples SET anomaly_score = ? WHERE sha256 = ?",
                (score, sha256.lower()),
            )
    def update_features(self, sha256: str, features: dict[str, Any]) -> None:
        with self._db.connect() as conn:
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
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE samples SET prediction = ? WHERE sha256 = ?",
                (prediction, sha256.lower()),
            )

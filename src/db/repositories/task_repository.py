"""Task log, family tracking, and temporal eval health."""

from __future__ import annotations

from typing import Any

from src.db.database import DatabaseManager
from src.db.repositories.ml_metadata_repository import MLMetadataRepository
from src.db.row_utils import row_to_dict, utc_now_iso


class TaskRepository:
    def __init__(self, db: DatabaseManager, ml: MLMetadataRepository) -> None:
        self._db = db
        self._ml = ml

    def create_task(
        self,
        trigger: str,
        sample_count: int,
        *,
        model_version: str = "",
    ) -> int:
        """Create a new chronological task and return its ID."""
        now = utc_now_iso()
        with self._db.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO task_log (created_at, sample_count, trigger, model_version)
                VALUES (?, ?, ?, ?)
                """,
                (now, sample_count, trigger, model_version or None),
            )
            return cursor.lastrowid or 0
    def fetch_task_holdout(self, task_id: int) -> list[dict[str, Any]]:
        """Fetch valid labeled features belonging to a specific task."""
        with self._db.connect() as conn:
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
        return [row_to_dict(r) for r in rows]
    def get_all_task_ids(self) -> list[int]:
        """Return list of all task IDs ordered by creation time."""
        with self._db.connect() as conn:
            rows = conn.execute("SELECT task_id FROM task_log ORDER BY task_id ASC").fetchall()
        return [int(r["task_id"]) for r in rows]
    def get_current_task_id(self) -> int:
        """Return the highest task_id, or 0 if none exist."""
        with self._db.connect() as conn:
            row = conn.execute("SELECT MAX(task_id) as max_id FROM task_log").fetchone()
        return int(row["max_id"]) if row and row["max_id"] is not None else 0
    def get_family_counts(self) -> dict[str, int]:
        """Return counts of active samples per family."""
        with self._db.connect() as conn:
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
    def temporal_split_health(
        self,
        *,
        train_ratio: float = 0.7,
        val_ratio: float = 0.15,
    ) -> dict[str, Any]:
        rows = self._ml.fetch_labeled_with_features()
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
    def update_family(self, sha256: str, family: str) -> None:
        """Update malware family and family counts."""
        sha = sha256.lower()
        fam = (family or "unknown").strip().lower()
        now = utc_now_iso()
        with self._db.connect() as conn:
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
    def update_sample_task(self, sha256: str, task_id: int) -> None:
        """Assign a sample to a task ID."""
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE samples SET task_id = ? WHERE sha256 = ?",
                (task_id, sha256.lower()),
            )

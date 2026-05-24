"""SQLite tracker for processed malware samples (facade)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import DB_PATH
from src.db.database import DatabaseManager
from src.db.repositories.collection_repository import CollectionRepository
from src.db.repositories.ml_metadata_repository import MLMetadataRepository
from src.db.repositories.quota_repository import QuotaRepository
from src.db.repositories.sample_repository import SampleRepository
from src.db.repositories.task_repository import TaskRepository
from src.db.row_utils import parse_utc, utc_now_iso, utc_today


def get_tracker(db_path: Path | None = None) -> MalwareTracker:
    """Factory using current config DB_PATH."""
    return MalwareTracker(db_path)


class MalwareTracker:
    """Persistent store for PE samples and features."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db = DatabaseManager(Path(db_path) if db_path else Path(DB_PATH))
        self._db.ensure_initialized()
        self.db_path = self._db.db_path
        self._samples = SampleRepository(self._db)
        self._ml = MLMetadataRepository(self._db)
        self._tasks = TaskRepository(self._db, self._ml)
        self._collection = CollectionRepository(self._db)
        self._quota = QuotaRepository(self._db)

    @staticmethod
    def utc_now_iso() -> str:
        return utc_now_iso()

    @staticmethod
    def utc_today() -> str:
        return utc_today()

    @staticmethod
    def _parse_utc(value: str):
        return parse_utc(value)

    def hash_exists(self, sha256: str) -> bool:
        return self._samples.hash_exists(sha256)

    def is_downloaded(self, sha256: str) -> bool:
        return self._samples.is_downloaded(sha256)

    def is_pending(self, sha256: str) -> bool:
        return self._samples.is_pending(sha256)

    def is_corrupted(self, sha256: str) -> bool:
        return self._samples.is_corrupted(sha256)

    def is_source_url_seen(self, url: str) -> bool:
        return self._samples.is_source_url_seen(url)

    def record_sample_source(
        self,
        sha256: str,
        *,
        source_provider: str | None = None,
        source_url: str | None = None,
    ) -> None:
        self._samples.record_sample_source(
            sha256, source_provider=source_provider, source_url=source_url
        )

    def fetch_pending_hashes(self, limit: int = 10) -> list[dict[str, Any]]:
        return self._samples.fetch_pending_hashes(limit)

    def insert_pending_hash(
        self,
        sha256: str,
        acquired_at: str | None = None,
        *,
        label: int = 1,
        source_first_seen: str | None = None,
    ) -> None:
        self._samples.insert_pending_hash(
            sha256, acquired_at, label=label, source_first_seen=source_first_seen
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
        self._samples.update_file_path(
            sha256,
            file_path,
            source_provider=source_provider,
            source_url=source_url,
            ingested_at=ingested_at,
            source_first_seen=source_first_seen,
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
        self._samples.insert_sample(
            sha256,
            file_path,
            acquired_at,
            features=features,
            label=label,
            prediction=prediction,
            anomaly_score=anomaly_score,
            status=status,
            reject_reason=reject_reason,
            rejected_at=rejected_at,
            source_provider=source_provider,
            source_url=source_url,
            ingested_at=ingested_at,
            source_first_seen=source_first_seen,
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
        self._samples.mark_corrupted(
            sha256,
            reason,
            file_path=file_path,
            acquired_at=acquired_at,
            label=label,
            source_first_seen=source_first_seen,
        )

    def get_sample(self, sha256: str) -> dict[str, Any] | None:
        return self._samples.get_sample(sha256)

    def fetch_chronological(self) -> list[dict[str, Any]]:
        return self._samples.fetch_chronological()

    def count_by_label(self) -> dict[int, int]:
        return self._samples.count_by_label()

    def update_features(self, sha256: str, features: dict[str, Any]) -> None:
        self._ml.update_features(sha256, features)

    def update_prediction(self, sha256: str, prediction: float) -> None:
        self._ml.update_prediction(sha256, prediction)

    def update_anomaly_score(self, sha256: str, score: float) -> None:
        self._ml.update_anomaly_score(sha256, score)

    def fetch_labeled_with_features(self) -> list[dict[str, Any]]:
        return self._ml.fetch_labeled_with_features()

    def fetch_labeled_with_features_and_family(self) -> list[dict[str, Any]]:
        return self._ml.fetch_labeled_with_features_and_family()

    def count_untrained_with_features(self) -> int:
        return self._ml.count_untrained_with_features()

    def fetch_untrained_with_features(self) -> list[dict[str, Any]]:
        return self._ml.fetch_untrained_with_features()

    def mark_all_trained(self, task_id: int | None = None) -> int:
        return self._ml.mark_all_trained(task_id)

    def update_family(self, sha256: str, family: str) -> None:
        self._tasks.update_family(sha256, family)

    def get_family_counts(self) -> dict[str, int]:
        return self._tasks.get_family_counts()

    def get_current_task_id(self) -> int:
        return self._tasks.get_current_task_id()

    def create_task(
        self,
        trigger: str,
        sample_count: int,
        *,
        model_version: str = "",
    ) -> int:
        return self._tasks.create_task(trigger, sample_count, model_version=model_version)

    def update_sample_task(self, sha256: str, task_id: int) -> None:
        self._tasks.update_sample_task(sha256, task_id)

    def get_all_task_ids(self) -> list[int]:
        return self._tasks.get_all_task_ids()

    def fetch_task_holdout(self, task_id: int) -> list[dict[str, Any]]:
        return self._tasks.fetch_task_holdout(task_id)

    def temporal_split_health(
        self,
        *,
        train_ratio: float = 0.7,
        val_ratio: float = 0.15,
    ) -> dict[str, Any]:
        return self._tasks.temporal_split_health(train_ratio=train_ratio, val_ratio=val_ratio)

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
        self._collection.record_provider_run(
            provider=provider,
            label=label,
            phase=phase,
            stage=stage,
            requested=requested,
            discovered=discovered,
            fresh=fresh,
            returned=returned,
            download_attempted=download_attempted,
            downloaded=downloaded,
            duplicate=duplicate,
            non_pe=non_pe,
            valid_pe=valid_pe,
            feature_extracted=feature_extracted,
            failed=failed,
        )

    def provider_recent_stats(
        self,
        provider: str,
        label: int | None,
        *,
        window: int = 10,
    ) -> dict[str, int]:
        return self._collection.provider_recent_stats(provider, label, window=window)

    def provider_success_rate(
        self, provider: str, label: int | None, *, window: int = 10
    ) -> float | None:
        return self._collection.provider_success_rate(provider, label, window=window)

    def is_provider_cooled_down(self, provider: str, label: int | None) -> bool:
        return self._collection.is_provider_cooled_down(provider, label)

    def rank_providers_by_yield(self, providers: list[str], label: int) -> list[str]:
        return self._collection.rank_providers_by_yield(providers, label)

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
        self._collection.record_candidate_seen(
            candidate_key=candidate_key,
            provider=provider,
            label=label,
            external_id=external_id,
            sha256=sha256,
            source_url=source_url,
            status=status,
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
        self._collection.record_candidate_outcome(
            candidate_key,
            status=status,
            error=error,
            sha256=sha256,
            increment_attempts=increment_attempts,
        )

    def increment_collection_counter(self, name: str) -> int:
        return self._collection.increment_collection_counter(name)

    def get_mb_pe_verdict(self, sha256: str) -> bool | None:
        return self._quota.get_mb_pe_verdict(sha256)

    def set_mb_pe_verdict(
        self,
        sha256: str,
        is_pe: bool,
        *,
        query_status: str = "ok",
    ) -> None:
        self._quota.set_mb_pe_verdict(sha256, is_pe, query_status=query_status)

    def mb_download_quota_available(self, *, limit: int | None = None) -> bool:
        return self._quota.mb_download_quota_available(limit=limit)

    def record_mb_download(self) -> bool:
        return self._quota.record_mb_download()

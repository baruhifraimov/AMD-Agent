"""Explicit Update tool — wraps MalwareTracker persistence for Rubric 2.6."""

from __future__ import annotations

from typing import Any

import src.db.tracker as db
from src.log import get_logger, vlog

logger = get_logger(__name__)


def insert_sample(
    tracker: db.MalwareTracker,
    sha256: str,
    file_path: str,
    acquired_at: str,
    *,
    features: dict[str, Any] | None = None,
    label: int | None = 1,
    **kwargs: Any,
) -> None:
    tracker.insert_sample(
        sha256,
        file_path,
        acquired_at,
        features=features,
        label=label,
        **kwargs,
    )


def update_file_path(
    tracker: db.MalwareTracker,
    sha256: str,
    file_path: str,
    **kwargs: Any,
) -> None:
    vlog(logger, "debug", "Update tool: file_path for %s", sha256[:12])
    tracker.update_file_path(sha256, file_path, **kwargs)


def update_features(tracker: db.MalwareTracker, sha256: str, features: dict[str, Any]) -> None:
    vlog(logger, "debug", "Update tool: features for %s", sha256[:12])
    tracker.update_features(sha256, features)


def update_prediction(tracker: db.MalwareTracker, sha256: str, prediction: float) -> None:
    vlog(logger, "debug", "Update tool: prediction for %s", sha256[:12])
    tracker.update_prediction(sha256, prediction)


def mark_corrupted(
    tracker: db.MalwareTracker,
    sha256: str,
    reason: str,
    **kwargs: Any,
) -> None:
    vlog(logger, "debug", "Update tool: mark_corrupted for %s", sha256[:12])
    tracker.mark_corrupted(sha256, reason, **kwargs)


def insert_pending_hash(
    tracker: db.MalwareTracker,
    sha256: str,
    *,
    acquired_at: str | None = None,
    label: int = 1,
    **kwargs: Any,
) -> None:
    vlog(logger, "debug", "Update tool: insert_pending_hash for %s", sha256[:12])
    tracker.insert_pending_hash(sha256, acquired_at=acquired_at, label=label, **kwargs)

"""Resolve drift/retrain labels from tracker and provider-verified metadata."""

from __future__ import annotations

import logging
from typing import Any

import src.db.tracker as db

logger = logging.getLogger(__name__)

VERIFIED_DISCOVERY_SOURCES = frozenset(
    {
        "malwarebazaar",
        "threatfox",
        "twitter",
        "twitter_cti",
        "sysinternals",
        "github",
        "dynamic_cti",
        "intel_rss",
        "intel_threatingestor",
        "intel_discover",
        "bootstrap_fast_path",
        "steady_explore",
        "steady_benign_balance",
        "intel_pending_queue",
    }
)

VERIFIED_SOURCE_PROVIDERS = frozenset(
    {
        "malwarebazaar",
        "threatfox",
        "twitter",
        "sysinternals",
        "github",
        "dynamic_cti",
    }
)


class GroundTruthResolver:
    """Accept labels only from DB trainable rows or provider-verified metadata."""

    def __init__(self, tracker: db.MalwareTracker | None = None) -> None:
        self.tracker = tracker or db.get_tracker()

    def resolve_label(
        self,
        sha256: str,
        metadata: dict[str, Any],
        *,
        tracker: db.MalwareTracker | None = None,
    ) -> int | None:
        tracker = tracker or self.tracker
        sha = sha256.lower()
        if len(sha) != 64:
            return None

        row = tracker.get_sample(sha)
        if row is not None:
            label = row.get("label")
            features = row.get("features")
            if label in (0, 1) and features:
                return int(label)

        return self._label_from_verified_metadata(metadata)

    def resolve(
        self,
        sha256: str,
        metadata: dict[str, Any],
        *,
        fallback: int | None = None,
        tracker: db.MalwareTracker | None = None,
    ) -> int | None:
        """Backward-compatible alias; fallback is ignored."""
        return self.resolve_label(sha256, metadata, tracker=tracker)

    @staticmethod
    def _label_from_verified_metadata(metadata: dict[str, Any]) -> int | None:
        if not metadata:
            return None

        discovery = str(
            metadata.get("discovery_source") or metadata.get("discovery_strategy") or ""
        ).lower()
        provider = str(metadata.get("source_provider") or metadata.get("provider") or "").lower()

        verified = discovery in VERIFIED_DISCOVERY_SOURCES or provider in VERIFIED_SOURCE_PROVIDERS
        if not verified:
            return None

        for key in ("label", "expected_label"):
            val = metadata.get(key)
            if val in (0, 1):
                return int(val)
        return None

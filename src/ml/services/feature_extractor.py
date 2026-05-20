"""PE feature extraction service."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.ml.features import extract_pe_features_with_error, extract_string_metrics


class PEFeatureExtractor:
    """Wraps pefile extraction plus raw-byte string metrics."""

    def extract(self, path: Path) -> tuple[dict[str, Any] | None, str | None]:
        features, error = extract_pe_features_with_error(path)
        if features is None:
            return None, error
        try:
            raw = path.read_bytes()
        except OSError as exc:
            return None, str(exc)
        string_count, avg_string_length = extract_string_metrics(raw)
        features["string_count"] = float(string_count)
        features["avg_string_length"] = float(avg_string_length)
        return features, None


class FeatureExtractorFactory:
    @staticmethod
    def get_default() -> PEFeatureExtractor:
        return PEFeatureExtractor()

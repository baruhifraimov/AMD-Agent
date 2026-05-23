"""Persistent ADWIN plus lightweight multivariate drift detection."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from river.drift import ADWIN

from src.config import (
    ADWIN_DELTA,
    ADWIN_PATH,
    DRIFT_CORR_SHIFT_THRESHOLD,
    DRIFT_MEAN_SHIFT_THRESHOLD,
    DRIFT_WINDOW_DAYS,
    DRIFT_MIN_WINDOW_SAMPLES,
    ensure_dirs,
)
from src.log import PHASE_DRIFT, get_logger, phase_log, vlog

logger = get_logger(__name__)


class DriftMonitor:
    """Persistent drift detector for entropy and selected feature streams."""

    def __init__(self, path: Path | None = None) -> None:
        ensure_dirs()
        self.path = path or ADWIN_PATH
        state = self._load()
        self.detector: ADWIN = state["detector"]
        self.vectors: list[np.ndarray] = state["vectors"]
        self.observed_at: list[float] = state.get("observed_at", [])
        self.last_stats: dict[str, float] = state.get("last_stats", {})

    def _new_detector(self) -> ADWIN:
        vlog(logger, "debug", "ADWIN detector delta=%.6f", ADWIN_DELTA)
        return ADWIN(delta=ADWIN_DELTA)

    def _new_state(self) -> dict[str, Any]:
        return {"detector": self._new_detector(), "vectors": [], "observed_at": [], "last_stats": {}}

    def _load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                loaded = joblib.load(self.path)
                if isinstance(loaded, ADWIN):
                    return {"detector": loaded, "vectors": [], "last_stats": {}}
                if isinstance(loaded, dict) and isinstance(loaded.get("detector"), ADWIN):
                    vectors = [
                        np.asarray(vec, dtype=np.float64)
                        for vec in loaded.get("vectors", [])
                        if np.asarray(vec).ndim == 1
                    ]
                    observed_at = [float(ts) for ts in loaded.get("observed_at", [])]
                    if len(observed_at) != len(vectors):
                        observed_at = [0.0 for _ in vectors]
                    return {
                        "detector": loaded["detector"],
                        "vectors": vectors,
                        "observed_at": observed_at,
                        "last_stats": dict(loaded.get("last_stats", {})),
                    }
                logger.warning("[%s] ADWIN state invalid type %s; recreating", PHASE_DRIFT, type(loaded))
            except Exception as exc:
                logger.warning("[%s] Failed to load ADWIN state: %s", PHASE_DRIFT, exc)
        return self._new_state()

    def save(self) -> None:
        joblib.dump(
            {
                "detector": self.detector,
                "vectors": self.vectors[-max(DRIFT_MIN_WINDOW_SAMPLES * 4, 1) :],
                "observed_at": self.observed_at[-max(DRIFT_MIN_WINDOW_SAMPLES * 4, 1) :],
                "last_stats": self.last_stats,
            },
            self.path,
        )

    @staticmethod
    def _timestamp(value: str | float | int | None) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str) and value.strip():
            raw = value.strip().replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError:
                try:
                    parsed = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    parsed = datetime.now(timezone.utc)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        return datetime.now(timezone.utc).timestamp()

    def _prune_time_window(self, now_ts: float) -> None:
        if DRIFT_WINDOW_DAYS <= 0 or not self.vectors:
            return
        cutoff = now_ts - float(DRIFT_WINDOW_DAYS * 24 * 60 * 60)
        pairs = [
            (vector, ts)
            for vector, ts in zip(self.vectors, self.observed_at)
            if ts == 0.0 or ts >= cutoff
        ]
        self.vectors = [item[0] for item in pairs]
        self.observed_at = [item[1] for item in pairs]

    def _multivariate_update(
        self,
        vector: np.ndarray | None,
        observed_at: str | float | int | None = None,
    ) -> bool:
        if vector is None or vector.size == 0:
            return False
        vec = np.nan_to_num(np.asarray(vector, dtype=np.float64), copy=False)
        ts = self._timestamp(observed_at)
        self.vectors.append(vec)
        self.observed_at.append(ts)
        self._prune_time_window(ts)
        max_vectors = max(DRIFT_MIN_WINDOW_SAMPLES * 4, 1)
        if len(self.vectors) > max_vectors:
            self.vectors = self.vectors[-max_vectors:]
            self.observed_at = self.observed_at[-max_vectors:]

        window = max(DRIFT_MIN_WINDOW_SAMPLES, 2)
        if len(self.vectors) < window * 2:
            return False

        prev = np.vstack(self.vectors[-window * 2 : -window])
        curr = np.vstack(self.vectors[-window:])
        prev_mean = np.mean(prev, axis=0)
        curr_mean = np.mean(curr, axis=0)
        prev_std = np.std(prev, axis=0) + 1e-6
        mean_shift = float(np.mean(np.abs(curr_mean - prev_mean) / prev_std))

        corr_shift = 0.0
        corr_dims = min(32, curr.shape[1])
        if corr_dims >= 2:
            prev_corr = np.nan_to_num(np.corrcoef(prev[:, :corr_dims], rowvar=False))
            curr_corr = np.nan_to_num(np.corrcoef(curr[:, :corr_dims], rowvar=False))
            corr_shift = float(np.mean(np.abs(curr_corr - prev_corr)))

        self.last_stats = {
            "mean_shift": mean_shift,
            "corr_shift": corr_shift,
            "window_samples": float(window),
            "window_days": float(DRIFT_WINDOW_DAYS),
        }
        drift = (
            mean_shift >= DRIFT_MEAN_SHIFT_THRESHOLD
            or corr_shift >= DRIFT_CORR_SHIFT_THRESHOLD
        )
        if drift:
            phase_log(
                logger,
                PHASE_DRIFT,
                "Multivariate drift mean_shift=%.4f corr_shift=%.4f",
                mean_shift,
                corr_shift,
            )
        return drift

    def update(
        self,
        value: float,
        vector: np.ndarray | None = None,
        observed_at: str | float | int | None = None,
    ) -> bool:
        """Add observation; return True if entropy or feature drift is detected."""
        self.detector.update(float(value))
        entropy_drift = bool(self.detector.drift_detected)
        if entropy_drift:
            phase_log(logger, PHASE_DRIFT, "ADWIN drift detected at value=%.4f", value)
        multivariate_drift = self._multivariate_update(vector, observed_at)
        self.save()
        return entropy_drift or multivariate_drift

    def reset_detector(self) -> None:
        self.detector = self._new_detector()
        self.vectors = []
        self.observed_at = []
        self.last_stats = {}
        self.save()

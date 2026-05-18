"""River ADWIN drift detection with disk persistence."""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
from river.drift import ADWIN

from src.config import ADWIN_PATH, ensure_dirs

logger = logging.getLogger(__name__)


class DriftMonitor:
    """Persistent ADWIN detector for section entropy streams."""

    def __init__(self, path: Path | None = None) -> None:
        ensure_dirs()
        self.path = path or ADWIN_PATH
        self.detector = self._load()

    def _load(self) -> ADWIN:
        if self.path.exists():
            try:
                return joblib.load(self.path)
            except Exception as exc:
                logger.warning("Failed to load ADWIN state: %s", exc)
        return ADWIN()

    def save(self) -> None:
        joblib.dump(self.detector, self.path)

    def update(self, value: float) -> bool:
        """Add observation; return True if drift detected."""
        self.detector.update(float(value))
        drift = bool(self.detector.drift_detected)
        if drift:
            logger.info("ADWIN drift detected at value=%.4f", value)
        self.save()
        return drift

    def reset_detector(self) -> None:
        self.detector = ADWIN()
        self.save()

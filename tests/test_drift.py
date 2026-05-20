"""Tests for ADWIN drift detection."""

from unittest.mock import patch

from src.ml.drift import DriftMonitor


def test_adwin_detects_shift(tmp_paths):
    monitor = DriftMonitor()
    monitor.reset_detector()
    drift = False
    for _ in range(50):
        monitor.update(0.1)
    for _ in range(50):
        if monitor.update(5.0):
            drift = True
            break
    assert drift


@patch("src.ml.drift.ADWIN_DELTA", 0.03)
def test_new_detector_uses_config_delta(tmp_paths):
    monitor = DriftMonitor()
    monitor.reset_detector()
    assert monitor.detector.delta == 0.03


@patch("src.ml.drift.ADWIN_DELTA", 0.05)
def test_high_delta_ignores_mild_shift(tmp_paths):
    monitor = DriftMonitor()
    monitor.reset_detector()
    drift = False
    for _ in range(200):
        monitor.update(0.1)
    for _ in range(200):
        if monitor.update(0.12):
            drift = True
            break
    assert drift is False


@patch("src.ml.drift.ADWIN_DELTA", 0.001)
def test_low_delta_detects_moderate_shift(tmp_paths):
    monitor = DriftMonitor()
    monitor.reset_detector()
    drift = False
    for _ in range(50):
        monitor.update(0.1)
    for _ in range(50):
        if monitor.update(5.0):
            drift = True
            break
    assert drift

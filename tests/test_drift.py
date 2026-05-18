"""Tests for ADWIN drift detection."""

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

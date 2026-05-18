"""Tests for classifier threshold and training."""

import numpy as np

from src.ml.classifier import fit_threshold


def test_fit_threshold_low_fpr():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    thr = fit_threshold(y, scores, target_fpr=0.25)
    assert 0.0 <= thr <= 1.0

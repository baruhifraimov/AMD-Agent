"""Tests for RetrainService threshold contract."""

from unittest.mock import patch

import numpy as np

from src.config import TARGET_FPR
from src.ml.classifier import fit_threshold
from src.ml.services.retrain import RetrainService


def test_retrain_service_exposes_target_fpr():
    assert RetrainService().target_fpr == TARGET_FPR


@patch("src.ml.services.classifier_service.retrain_model")
def test_retrain_service_delegates(mock_retrain):
    X = np.zeros((10, 17))
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    mock_retrain.return_value = {"threshold": 0.42}
    bundle = RetrainService().retrain(X, y)
    mock_retrain.assert_called_once_with(X, y)
    assert bundle["threshold"] == 0.42


def test_fit_threshold_recomputed_on_mixed_validation():
    y_true = np.array([0, 0, 1, 1])
    y_score = np.array([0.1, 0.2, 0.8, 0.9])
    thr = fit_threshold(y_true, y_score, target_fpr=TARGET_FPR)
    assert 0.0 < thr < 1.0

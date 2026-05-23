"""Tests for dynamic TARGET_FPR scaling by trainable benign count."""

from src.config import (
    TARGET_FPR,
    TARGET_FPR_BOOTSTRAP,
    TARGET_FPR_GROWTH,
    get_dynamic_target_fpr,
)
from src.ml.classifier import resolve_target_fpr


def test_get_dynamic_target_fpr_bootstrap_tier():
    assert get_dynamic_target_fpr(0) == TARGET_FPR_BOOTSTRAP
    assert get_dynamic_target_fpr(100) == 0.05
    assert get_dynamic_target_fpr(999) == 0.05


def test_get_dynamic_target_fpr_growth_tier():
    assert get_dynamic_target_fpr(1000) == TARGET_FPR_GROWTH
    assert get_dynamic_target_fpr(1500) == 0.01
    assert get_dynamic_target_fpr(4999) == 0.01


def test_get_dynamic_target_fpr_production_tier():
    assert get_dynamic_target_fpr(5000) == TARGET_FPR
    assert get_dynamic_target_fpr(6000) == 0.001


def test_resolve_target_fpr_explicit_count():
    assert resolve_target_fpr(42) == TARGET_FPR_BOOTSTRAP
    assert resolve_target_fpr(2500) == TARGET_FPR_GROWTH
    assert resolve_target_fpr(8000) == TARGET_FPR

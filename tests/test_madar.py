"""Tests for MADAR replay buffer."""

import numpy as np
from src.ml.madar import build_madar_replay, build_replay_indices


def test_madar_family_aware_replay():
    rng = np.random.default_rng(42)
    # 300 samples total, 100 benign, 200 malware
    # Malware split into families: "famA" (100), "famB" (80), "famC" (20)
    X = rng.normal(size=(300, 15))
    y = np.array([0] * 100 + [1] * 200, dtype=int)
    families = ["unknown"] * 100 + ["famA"] * 100 + ["famB"] * 80 + ["famC"] * 20
    
    # ratio budget -> famA gets ~50%, famB ~40%, famC ~10% of malware budget
    idx = build_madar_replay(
        X, y, families, total_budget=100, 
        class_ratio=0.5, budget_strategy="ratio",
        contamination=0.1, anomalous_ratio=0.5
    )
    
    assert len(idx) <= 100
    replay_labels = y[idx]
    
    # Should have roughly equal benign and malware
    benign_count = np.sum(replay_labels == 0)
    malware_count = np.sum(replay_labels == 1)
    
    assert 45 <= benign_count <= 55
    assert 45 <= malware_count <= 55
    
    # Check family presence
    replay_families = [families[i] for i in idx if y[i] == 1]
    assert "famA" in replay_families
    assert "famB" in replay_families
    # famC is small, but under ratio might get a couple samples
    
def test_madar_uniform_budget():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(300, 15))
    y = np.array([0] * 100 + [1] * 200, dtype=int)
    families = ["unknown"] * 100 + ["famA"] * 100 + ["famB"] * 80 + ["famC"] * 20
    
    idx = build_madar_replay(
        X, y, families, total_budget=60, 
        class_ratio=0.5, budget_strategy="uniform",
    )
    
    replay_families = [families[i] for i in idx if y[i] == 1]
    fam_counts = {f: replay_families.count(f) for f in set(replay_families)}
    
    # malware budget = 30. 3 families -> 10 each
    assert fam_counts.get("famA", 0) == 10
    assert fam_counts.get("famB", 0) == 10
    assert fam_counts.get("famC", 0) == 10

def test_legacy_api_fallback():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(500, 15))
    idx = build_replay_indices(X, budget=200)
    assert len(idx) <= 200
    assert len(idx) >= 1

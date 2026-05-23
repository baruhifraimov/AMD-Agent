"""MADAR exact-replay continual learning with family-aware Isolation Forest sampling."""

from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from src.config import (
    FEATURE_NAMES,
    MADAR_ANOMALOUS_RATIO,
    MADAR_BUDGET_STRATEGY,
    MADAR_CLASS_RATIO,
    MADAR_CONTAMINATION,
    REPLAY_BUDGET,
)
from src.ml.classifier import (
    _bundle_feature_compatible,
    continue_training,
    load_bundle,
    retrain_model,
)
from src.ml.features import vectorize_batch
from src.log import PHASE_RETRAIN, get_logger, phase_log, vlog
from src.ml.replay_budget import RatioBudget, UniformBudget

logger = get_logger(__name__)


def select_family_replay(
    X_family: np.ndarray,
    budget: int,
    contamination: float = 0.1,
    anomalous_ratio: float = 0.5,
) -> np.ndarray:
    """Isolation Forest split: 50% anomalous + 50% representative."""
    if len(X_family) <= budget:
        return np.arange(len(X_family))
    if budget <= 0:
        return np.array([], dtype=int)

    iso = IsolationForest(contamination=contamination, random_state=42)
    iso.fit(X_family)
    scores = -iso.decision_function(X_family)
    order = np.argsort(scores)

    n_anomalous = int(budget * anomalous_ratio)
    n_representative = budget - n_anomalous

    anomalous_idx = order[-n_anomalous:] if n_anomalous > 0 else np.array([], dtype=int)
    representative_idx = order[:n_representative] if n_representative > 0 else np.array([], dtype=int)

    return np.unique(np.concatenate([anomalous_idx, representative_idx]))


def _sample_goodware(X_pool: np.ndarray, global_indices: np.ndarray, budget: int) -> np.ndarray:
    """Random sampling for benign class."""
    if len(X_pool) <= budget:
        return global_indices
    if budget <= 0:
        return np.array([], dtype=int)
    
    rng = np.random.default_rng(42)
    chosen = rng.choice(len(X_pool), size=budget, replace=False)
    return global_indices[chosen]


def build_madar_replay(
    X_hist: np.ndarray,
    y_hist: np.ndarray,
    families_hist: list[str],
    total_budget: int,
    *,
    class_ratio: float = MADAR_CLASS_RATIO,
    budget_strategy: str = MADAR_BUDGET_STRATEGY,
    contamination: float = MADAR_CONTAMINATION,
    anomalous_ratio: float = MADAR_ANOMALOUS_RATIO,
) -> np.ndarray:
    """MADAR paper-faithful replay selection with family-aware budgeting."""
    if len(X_hist) == 0 or total_budget <= 0:
        return np.array([], dtype=int)
    
    global_indices = np.arange(len(X_hist))
    
    # 1. Split by label
    benign_mask = y_hist == 0
    malware_mask = y_hist == 1
    
    goodware_budget = int(total_budget * class_ratio)
    malware_budget = total_budget - goodware_budget
    
    # 2. Goodware sampling
    goodware_indices = _sample_goodware(
        X_hist[benign_mask], 
        global_indices[benign_mask], 
        goodware_budget
    )
    
    # 3. Malware: family-aware budgeting
    strategy = RatioBudget() if budget_strategy == "ratio" else UniformBudget()
    malware_families = [f for f, m in zip(families_hist, malware_mask) if m]
    family_counts = dict(Counter(malware_families))
    family_budgets = strategy.allocate(family_counts, malware_budget)
    
    # 4. Within each family: IF-based anomalous/representative selection
    malware_indices = []
    for family, fam_budget in family_budgets.items():
        if fam_budget <= 0:
            continue
            
        family_mask = np.array([
            m and f == family 
            for f, m in zip(families_hist, malware_mask)
        ])
        
        if not family_mask.any():
            continue
            
        X_family = X_hist[family_mask]
        family_global = global_indices[family_mask]
        
        local_selected = select_family_replay(
            X_family, fam_budget, contamination, anomalous_ratio
        )
        malware_indices.extend(family_global[local_selected].tolist())
    
    combined = np.concatenate([goodware_indices, malware_indices])
    return np.unique(np.asarray(combined, dtype=int)) if len(combined) > 0 else np.array([], dtype=int)


def build_replay_indices(
    X_hist: np.ndarray,
    y_hist: np.ndarray | None = None,
    budget: int = REPLAY_BUDGET,
    contamination: float = MADAR_CONTAMINATION,
) -> np.ndarray:
    """Legacy API — delegates to MADAR with 'unknown' families."""
    if y_hist is None:
        y_hist = np.ones(len(X_hist), dtype=int)
    families_hist = ["unknown"] * len(X_hist)
    return build_madar_replay(
        X_hist, y_hist, families_hist, budget,
        contamination=contamination
    )


def madar_retrain(
    historical_features: list[dict],
    new_batch: list[dict],
    historical_labels: list[int],
    new_labels: list[int],
    *,
    historical_families: list[str] | None = None,
    force_feature_reselection: bool = False,
    budget_strategy: str = MADAR_BUDGET_STRATEGY,
    init_model: dict[str, Any] | None = None,
    model_metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """MADAR-faithful retrain: family-aware replay + model continuation."""
    X_hist = vectorize_batch(historical_features) if historical_features else np.empty((0, 0))
    X_new = vectorize_batch(new_batch) if new_batch else np.empty((0, 0))

    if X_hist.size == 0 and X_new.size == 0:
        raise ValueError("No features for MADAR retrain")

    y_hist = np.array(historical_labels, dtype=int) if historical_labels else np.array([])
    families_hist = historical_families or ["unknown"] * len(X_hist)
    
    replay_idx = build_madar_replay(
        X_hist, y_hist, families_hist, REPLAY_BUDGET,
        budget_strategy=budget_strategy
    )
    
    n_features = len(FEATURE_NAMES)
    X_replay = X_hist[replay_idx] if len(replay_idx) else np.empty(
        (0, X_new.shape[1] if X_new.size else n_features)
    )
    y_replay = y_hist[replay_idx] if len(replay_idx) else np.array([])

    y_new = np.array(new_labels, dtype=int) if new_labels else np.array([])

    if X_replay.size and X_new.size:
        X = np.vstack([X_replay, X_new])
        y = np.concatenate([y_replay, y_new])
    elif X_new.size:
        X, y = X_new, y_new
    else:
        X, y = X_replay, y_replay

    frozen: list[int] | None = None
    existing = init_model or load_bundle()
    if not force_feature_reselection and existing and _bundle_feature_compatible(existing):
        raw = existing.get("selected_feature_indices")
        if isinstance(raw, list) and raw:
            frozen = [int(i) for i in raw]

    phase_log(
        logger,
        PHASE_RETRAIN,
        "MADAR retrain: replay=%d new=%d total=%d feature_reselection=%s",
        len(replay_idx),
        len(new_batch),
        len(y),
        force_feature_reselection,
    )

    if init_model and _bundle_feature_compatible(init_model):
        try:
            vlog(logger, "info", "MADAR continuing training from previous bundle weights")
            return continue_training(
                X, y, X, y,  # Note: normally should use validation split
                old_bundle=init_model,
                model_metadata=model_metadata,
            )
        except Exception as exc:
            logger.warning("[%s] continue_training failed: %s; falling back to retrain_model", PHASE_RETRAIN, exc)

    return retrain_model(X, y, frozen_feature_indices=frozen, model_metadata=model_metadata)

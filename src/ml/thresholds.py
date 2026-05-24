"""FPR target scaling from trainable benign sample count in SQLite."""

# --- Production FPR ceiling and benign-volume tiers ---
# Below 1k benign: 5% target; 1k–5k: 1%; 5k+: 0.1% (see get_dynamic_target_fpr)

TARGET_FPR = 0.001
TARGET_FPR_BOOTSTRAP = 0.05
TARGET_FPR_GROWTH = 0.01
TARGET_FPR_BENIGN_TIER_BOOTSTRAP = 1000
TARGET_FPR_BENIGN_TIER_PRODUCTION = 5000


def get_dynamic_target_fpr(num_benign_samples: int) -> float:
    """Scale FPR target with trainable benign volume in SQLite."""
    if num_benign_samples < TARGET_FPR_BENIGN_TIER_BOOTSTRAP:
        return TARGET_FPR_BOOTSTRAP
    if num_benign_samples < TARGET_FPR_BENIGN_TIER_PRODUCTION:
        return TARGET_FPR_GROWTH
    return TARGET_FPR

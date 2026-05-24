"""Filesystem paths (local vs Docker) and directory bootstrap."""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# --- Paths and storage (local vs Docker) ---

_in_container = Path("/data").exists() and os.getenv("AMD_AGENT_CONTAINER") == "1"
if _in_container:
    SANDBOX_DIR = Path("/tmp/sandbox")
    DB_PATH = Path("/data/malware_tracker.db")
    BENIGN_DIR = Path("/data/benign")
    MODEL_PATH = Path("/data/models/model.pkl")
    ADWIN_PATH = Path("/data/models/adwin.joblib")
    EVAL_LOG_PATH = Path("/data/evaluation_log.jsonl")
    EVAL_STATE_PATH = Path("/data/evaluation_state.json")
    DRIFT_LOG_PATH = Path("/data/drift_log.jsonl")
    MODEL_UPDATE_LOG_PATH = Path("/data/model_update_log.jsonl")
    TRAINING_HISTORY_PATH = Path("/data/training_history.jsonl")
    LOG_PATH = Path("/data/logs/amd-agent.log")
    FIGURES_DIR = Path("/data/figures")
    REPOS_DIR = Path("/data/repos")
else:
    SANDBOX_DIR = PROJECT_ROOT / "data" / "sandbox"
    DB_PATH = PROJECT_ROOT / "data" / "malware_tracker.db"
    BENIGN_DIR = PROJECT_ROOT / "data" / "benign"
    MODEL_PATH = PROJECT_ROOT / "data" / "models" / "model.pkl"
    ADWIN_PATH = PROJECT_ROOT / "data" / "models" / "adwin.joblib"
    EVAL_LOG_PATH = PROJECT_ROOT / "data" / "evaluation_log.jsonl"
    EVAL_STATE_PATH = PROJECT_ROOT / "data" / "evaluation_state.json"
    DRIFT_LOG_PATH = PROJECT_ROOT / "data" / "drift_log.jsonl"
    MODEL_UPDATE_LOG_PATH = PROJECT_ROOT / "data" / "model_update_log.jsonl"
    TRAINING_HISTORY_PATH = PROJECT_ROOT / "data" / "training_history.jsonl"
    LOG_PATH = PROJECT_ROOT / "data" / "logs" / "amd-agent.log"
    FIGURES_DIR = PROJECT_ROOT / "report" / "figures"
    REPOS_DIR = PROJECT_ROOT / "data" / "repos"


def ensure_dirs() -> None:
    """Create required directories (paths module; prefer src.config.ensure_dirs for tests)."""
    for path in (
        SANDBOX_DIR,
        DB_PATH.parent,
        MODEL_PATH.parent,
        BENIGN_DIR,
        FIGURES_DIR,
        EVAL_STATE_PATH.parent,
        DRIFT_LOG_PATH.parent,
        MODEL_UPDATE_LOG_PATH.parent,
        TRAINING_HISTORY_PATH.parent,
        LOG_PATH.parent,
        REPOS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)

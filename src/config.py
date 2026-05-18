"""Application configuration and paths."""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# MalwareBazaar API
API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = "infected"
AUTH_KEY_ENV = "MALWAREBAZAAR_AUTH_KEY"

# Sandbox: container vs local dev
_in_container = Path("/data").exists() and os.getenv("AMD_AGENT_CONTAINER") == "1"
if _in_container:
    SANDBOX_DIR = Path("/tmp/sandbox")
    DB_PATH = Path("/data/malware_tracker.db")
    BENIGN_DIR = Path("/data/benign")
    MODEL_PATH = Path("/data/models/model.pkl")
    ADWIN_PATH = Path("/data/models/adwin.joblib")
    EVAL_LOG_PATH = Path("/data/evaluation_log.jsonl")
    FIGURES_DIR = Path("/data/figures")
else:
    SANDBOX_DIR = PROJECT_ROOT / "data" / "sandbox"
    DB_PATH = PROJECT_ROOT / "data" / "malware_tracker.db"
    BENIGN_DIR = PROJECT_ROOT / "data" / "benign"
    MODEL_PATH = PROJECT_ROOT / "data" / "models" / "model.pkl"
    ADWIN_PATH = PROJECT_ROOT / "data" / "models" / "adwin.joblib"
    EVAL_LOG_PATH = PROJECT_ROOT / "data" / "evaluation_log.jsonl"
    FIGURES_DIR = PROJECT_ROOT / "report" / "figures"

REPLAY_BUDGET = 2000
MIN_TRAIN_MALWARE = 20
MIN_TRAIN_BENIGN = 5
PE_FETCH_LIMIT = 10
TARGET_FPR = 0.001

# Benign / malware collection balance
MIN_BENIGN_FOR_FPR = 10
TARGET_MALWARE_BENIGN_RATIO = 10.0
BENIGN_PROVIDER_NAMES = ("sysinternals", "github")
ALLOW_LOCAL_BENIGN_ENV = "AMD_ALLOW_LOCAL_BENIGN"

# Sysinternals benign source
SYSINTERNALS_BASE_URLS = (
    "https://live.sysinternals.com/",
    "https://live.sysinternals.com/tools/",
)

# GitHub Releases benign source
GITHUB_API_URL = "https://api.github.com"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
GITHUB_BENIGN_REPOS: list[tuple[str, str]] = [
    ("microsoft", "Sysinternals"),
    ("NotepadPlusPlus", "notepad-plus-plus"),
    ("git-for-windows", "git"),
]

EXEC_API_NAMES = frozenset(
    {
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
        "RtlCreateUserThread",
    }
)

FEATURE_NAMES = [
    "dos_header_size",
    "pe_header_offset",
    "rich_header_present",
    "rich_entropy",
    "num_sections",
    "avg_section_entropy",
    "max_section_entropy",
    "num_imported_dlls",
    "num_imported_apis",
    "has_exec_apis",
    "image_size",
    "entry_point",
    "subsystem",
    "dll_characteristics",
    "timestamp",
]


def ensure_dirs() -> None:
    """Create required directories."""
    for path in (
        SANDBOX_DIR,
        DB_PATH.parent,
        MODEL_PATH.parent,
        BENIGN_DIR,
        FIGURES_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def get_auth_key() -> str:
    key = os.getenv(AUTH_KEY_ENV, "")
    if not key:
        raise ValueError(f"Missing {AUTH_KEY_ENV} environment variable")
    return key


def get_github_token() -> str:
    return os.getenv(GITHUB_TOKEN_ENV, "").strip()


def allow_local_benign() -> bool:
    return os.getenv(ALLOW_LOCAL_BENIGN_ENV, "").strip() in ("1", "true", "yes")

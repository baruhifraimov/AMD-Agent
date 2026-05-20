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
MIN_TRAIN_MALWARE = 100
MIN_TRAIN_BENIGN = 100
PE_FETCH_LIMIT = 10
TARGET_FPR = 0.001

# Benign / malware collection balance
MIN_BENIGN_FOR_FPR = MIN_TRAIN_BENIGN
TARGET_MALWARE_BENIGN_RATIO = 1.0
BENIGN_PROVIDER_NAMES = ("sysinternals", "github")
ALLOW_LOCAL_BENIGN_ENV = "AMD_ALLOW_LOCAL_BENIGN"
THREAT_QUEUE_ENABLED_ENV = "AMD_THREAT_QUEUE_ENABLED"
INTEL_INGEST_ENABLED_ENV = "AMD_INTEL_INGEST_ENABLED"
INTEL_MIN_POLL_INTERVAL_ENV = "AMD_INTEL_MIN_POLL_INTERVAL"
INTEL_MAX_POLL_INTERVAL_ENV = "AMD_INTEL_MAX_POLL_INTERVAL"
INTEL_PENDING_CAP_MULT_ENV = "AMD_INTEL_PENDING_CAP_MULT"
CTI_DOWNLOAD_ALLOWLIST_ENV = "AMD_CTI_DOWNLOAD_ALLOWLIST"
PE_DOWNLOAD_MAX_BYTES_ENV = "AMD_PE_DOWNLOAD_MAX_BYTES"
OLLAMA_SOURCE_SELECTION_ENV = "AMD_OLLAMA_SOURCE_SELECTION"
OLLAMA_BASE_URL_ENV = "AMD_OLLAMA_BASE_URL"
OLLAMA_MODEL_ENV = "AMD_OLLAMA_MODEL"
OLLAMA_TIMEOUT_ENV = "AMD_OLLAMA_TIMEOUT"
CAPA_RULES_DIR_ENV = "AMD_CAPA_RULES_DIR"
REPORT_LANGUAGE_ENV = "AMD_REPORT_LANGUAGE"
THREATINGESTOR_ENABLED_ENV = "AMD_THREATINGESTOR_ENABLED"
THREATINGESTOR_CONFIG_ENV = "AMD_THREATINGESTOR_CONFIG"
THREATINGESTOR_ARTIFACT_DB_ENV = "AMD_THREATINGESTOR_ARTIFACT_DB"
THREATINGESTOR_BRIDGE_INTERVAL_ENV = "AMD_THREATINGESTOR_BRIDGE_INTERVAL"
THREATINGESTOR_BRIDGE_BATCH_ENV = "AMD_THREATINGESTOR_BRIDGE_BATCH"
THREATINGESTOR_SLEEP_BOOTSTRAP_ENV = "AMD_THREATINGESTOR_SLEEP_BOOTSTRAP"
THREATINGESTOR_SLEEP_STEADY_ENV = "AMD_THREATINGESTOR_SLEEP_STEADY"


def threat_queue_enabled() -> bool:
    return os.getenv(THREAT_QUEUE_ENABLED_ENV, "1").strip() not in ("0", "false", "no")


def intel_ingest_enabled() -> bool:
    return os.getenv(INTEL_INGEST_ENABLED_ENV, "1").strip() not in ("0", "false", "no")


def ollama_source_selection_enabled() -> bool:
    return os.getenv(OLLAMA_SOURCE_SELECTION_ENV, "1").strip() not in ("0", "false", "no")


def threatingestor_enabled() -> bool:
    return os.getenv(THREATINGESTOR_ENABLED_ENV, "1").strip() not in ("0", "false", "no")


THREAT_QUEUE_ENABLED = threat_queue_enabled()
THREATINGESTOR_ENABLED = threatingestor_enabled()
INTEL_INGEST_ENABLED = intel_ingest_enabled()
INTEL_MIN_POLL_INTERVAL = int(os.getenv(INTEL_MIN_POLL_INTERVAL_ENV, "60"))
INTEL_MAX_POLL_INTERVAL = int(os.getenv(INTEL_MAX_POLL_INTERVAL_ENV, "3600"))
INTEL_PENDING_CAP_MULT = int(os.getenv(INTEL_PENDING_CAP_MULT_ENV, "3"))

# Local LLM / explainability
OLLAMA_BASE_URL = os.getenv(OLLAMA_BASE_URL_ENV, "http://localhost:11434").strip()
OLLAMA_MODEL = os.getenv(OLLAMA_MODEL_ENV, "llama3.1:8b").strip()
OLLAMA_TIMEOUT = float(os.getenv(OLLAMA_TIMEOUT_ENV, "8"))
CAPA_RULES_DIR = Path(os.getenv(CAPA_RULES_DIR_ENV, "/opt/capa-rules")).expanduser()
REPORT_LANGUAGE = os.getenv(REPORT_LANGUAGE_ENV, "English").strip() or "English"
_default_threatingestor_artifact_db = (
    Path("/data/threatingestor_artifacts.db")
    if _in_container
    else PROJECT_ROOT / "data" / "threatingestor_artifacts.db"
)
THREATINGESTOR_ARTIFACT_DB = Path(
    os.getenv(THREATINGESTOR_ARTIFACT_DB_ENV, str(_default_threatingestor_artifact_db))
).expanduser()
THREATINGESTOR_BRIDGE_INTERVAL = int(os.getenv(THREATINGESTOR_BRIDGE_INTERVAL_ENV, "30"))
THREATINGESTOR_BRIDGE_BATCH = int(os.getenv(THREATINGESTOR_BRIDGE_BATCH_ENV, "100"))
_default_threatingestor_config = (
    Path("/app/threatingestor_config.yml")
    if _in_container
    else PROJECT_ROOT / "threatingestor_config.yml"
)
THREATINGESTOR_CONFIG_PATH = Path(
    os.getenv(THREATINGESTOR_CONFIG_ENV, str(_default_threatingestor_config))
).expanduser()
THREATINGESTOR_SLEEP_BOOTSTRAP = int(os.getenv(THREATINGESTOR_SLEEP_BOOTSTRAP_ENV, "60"))
THREATINGESTOR_SLEEP_STEADY = int(os.getenv(THREATINGESTOR_SLEEP_STEADY_ENV, "900"))

# Dynamic CTI discovery limits
CTI_SEARCH_LIMIT = int(os.getenv("AMD_CTI_SEARCH_LIMIT", "5"))
CTI_PAGE_LIMIT = int(os.getenv("AMD_CTI_PAGE_LIMIT", "5"))
CTI_PAGE_MAX_BYTES = int(os.getenv("AMD_CTI_PAGE_MAX_BYTES", "250000"))
CTI_REQUEST_TIMEOUT = float(os.getenv("AMD_CTI_REQUEST_TIMEOUT", "20"))
PE_DOWNLOAD_MAX_BYTES = int(os.getenv(PE_DOWNLOAD_MAX_BYTES_ENV, os.getenv("AMD_CTI_PAGE_MAX_BYTES", "250000")))
_default_allowlist = "github.com,raw.githubusercontent.com,objects.githubusercontent.com"
CTI_DOWNLOAD_ALLOWLIST = tuple(
    d.strip().lower()
    for d in os.getenv(CTI_DOWNLOAD_ALLOWLIST_ENV, _default_allowlist).split(",")
    if d.strip()
)

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
    "string_count",
    "avg_string_length",
]


def ensure_dirs() -> None:
    """Create required directories."""
    for path in (
        SANDBOX_DIR,
        DB_PATH.parent,
        MODEL_PATH.parent,
        BENIGN_DIR,
        FIGURES_DIR,
        THREATINGESTOR_ARTIFACT_DB.parent,
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

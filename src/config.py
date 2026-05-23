"""Application configuration and paths.

Edit tuning constants here; secrets live in `.env` (see `.env.example`).
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

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
    LOG_PATH = PROJECT_ROOT / "data" / "logs" / "amd-agent.log"
    FIGURES_DIR = PROJECT_ROOT / "report" / "figures"
    REPOS_DIR = PROJECT_ROOT / "data" / "repos"

# --- Secrets and environment (see .env.example) ---

# MALWAREBAZAAR_AUTH_KEY, GITHUB_TOKEN, MALSHARE_API_KEY: use get_*() helpers below.
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
OLLAMA_BASE_URL = os.getenv("AMD_OLLAMA_BASE_URL").strip()
OLLAMA_MODEL = os.getenv("AMD_OLLAMA_MODEL").strip()

# --- Scheduler and bootstrap ---

# Daemon: `python -m src.graph --daemon`
SCHED_ENABLED = False
SCHED_INTERVAL_SECONDS = 1800
SCHED_MAX_RUNS: int | None = None
SCHED_RUN_ON_START = True
SCHED_JITTER_SECONDS = 60
SCHED_ERROR_BACKOFF_SECONDS = 60
SCHED_MAX_BACKOFF_SECONDS = 3600

# Bootstrap: `python -m src.graph --bootstrap`
BOOTSTRAP_MAX_RUNS = 60
BOOTSTRAP_INTERVAL_SECONDS = 10

# --- Logging ---

VERBOSE = False  # True = detailed per-item console logs (file always full detail)
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

# Ollama request/response trace (full payloads always in amd-agent.log)
OLLAMA_LOG_DETAIL = True
OLLAMA_LOG_MAX_CHARS = 8000
OLLAMA_LOG_CONSOLE_PREVIEW = 500

# --- Feature flags ---

ALLOW_LOCAL_BENIGN = False
MALSHARE_ENABLED = False
MB_FALLBACK_MALSHARE = False
PE_SOURCE_DISCOVERY_ENABLED = False
CTI_SEED_SOURCES_ENABLED = True
OLLAMA_ENABLED = True
OLLAMA_SOURCE_SELECTION_ENABLED = True
FORCED_BENIGN_PROVIDER: str | None = None

# --- Machine learning (training, FPR, drift, MADAR, feature version) ---

REPLAY_BUDGET = 3000
MIN_TRAIN_MALWARE = 25
MIN_TRAIN_BENIGN = 25
PE_FETCH_LIMIT = 10
THRESHOLD_RETRAIN_MIN_NEW_SAMPLES = 20  # retrain when N untrained featured samples accumulate

TARGET_FPR = 0.001  # production ceiling (5k+ trainable benign in DB)
TARGET_FPR_BOOTSTRAP = 0.05  # <1k benign
TARGET_FPR_GROWTH = 0.01  # 1k–4,999 benign
TARGET_FPR_BENIGN_TIER_BOOTSTRAP = 1000
TARGET_FPR_BENIGN_TIER_PRODUCTION = 5000


def get_dynamic_target_fpr(num_benign_samples: int) -> float:
    """Scale FPR target with trainable benign volume in SQLite."""
    if num_benign_samples < TARGET_FPR_BENIGN_TIER_BOOTSTRAP:
        return TARGET_FPR_BOOTSTRAP
    if num_benign_samples < TARGET_FPR_BENIGN_TIER_PRODUCTION:
        return TARGET_FPR_GROWTH
    return TARGET_FPR


FEATURE_SELECTION_K = 384
OPTUNA_TRIALS = 25
OPTUNA_TIMEOUT = 300
REPLAY_FRACTION = 0.3  # DEPRECATED

# Drift (DEV: sensitive — production targets noted inline)
ADWIN_DELTA = 0.002
DRIFT_WINDOW_DAYS = 0  # 0 = disable time pruning (_prune_time_window no-op)
DRIFT_MIN_WINDOW_SAMPLES = 5  # multivariate needs len(vectors) >= 10 (5 * 2)
DRIFT_MEAN_SHIFT_THRESHOLD = 0.2  # production: 1.5
DRIFT_CORR_SHIFT_THRESHOLD = 0.1  # production: 0.35

# MADAR replay and LightGBM continuation
MADAR_CONTAMINATION = 0.1
MADAR_ANOMALOUS_RATIO = 0.5
MADAR_CLASS_RATIO = 0.5
MADAR_BUDGET_STRATEGY = "ratio"
CONTINUATION_TREES = 50
MAX_TOTAL_TREES = 500
MODEL_ARCHIVE_DEPTH = 5

FEATURE_SET_VERSION = "ember_static_v1"
FEATURE_DIM = 2304

# --- Semantic hash filter (Ollama-assisted CTI) ---

SEMANTIC_MIN_CONFIDENCE = 0.6
SEMANTIC_REQUIRE_TECHNICAL_REPORT = False

# --- Evaluation (TESSERACT) ---

EVAL_EVERY_RUNS = 10
EVAL_SKIP_BOOTSTRAP = True
TESSERACT_MIXED_UNTIL_HEALTHY = True

# --- Collection, intel, and discovery ---

MIN_BENIGN_FOR_FPR = MIN_TRAIN_BENIGN
TARGET_MALWARE_BENIGN_RATIO = 1.0
BENIGN_PROVIDER_NAMES = ("sysinternals", "github", "benign_net")
IMBALANCE_ALERT_RATIO = 0.5

MALWARE_FALLBACK_PROVIDERS = ("malshare", "threatfox", "otx_pulse_cti")
FALLBACK_PE_CHECK_MULT = 1
PE_DOWNLOAD_MAX_BYTES = 250000
BENIGN_NET_REPO_URL = "https://github.com/bormaa/Benign-NET.git"
BENIGN_NET_MAX_DISCOVER = 20
PE_DISCOVERY_MAX_URLS = 8
MIN_PE_SOURCES = 3

INTEL_MIN_POLL_INTERVAL = 60
INTEL_MAX_POLL_INTERVAL = 3600
PROVIDER_COOLDOWN_ZERO_RUNS = 3
PROVIDER_COOLDOWN_SECONDS = 43200
PROVIDER_COOLDOWN_MIN_ATTEMPTS = 5
STEADY_BENIGN_EVERY_N = 4

# --- External APIs (MalwareBazaar, CTI, OTX, Ollama, benign sources) ---

# MalwareBazaar
API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = "infected"
MB_CIRCUIT_FAILURE_THRESHOLD = 3
MB_CIRCUIT_OPEN_SECONDS = 120.0
MB_CIRCUIT_OPEN_SECONDS_429 = 3600.0
MB_MIN_REQUEST_INTERVAL = 1.5
MB_USER_AGENT = (
    "AMD-Agent/1.0 (malware-ml-research; contact via MALWAREBAZAAR_AUTH_KEY holder)"
)
MB_USER_AGENT_CONTACT = ""
MB_INFO_CACHE_TTL_DAYS = 30
MB_DAILY_DOWNLOAD_LIMIT = 1900
MB_MAX_INFO_CALLS_PER_RUN = 0

# CTI web fetch
CTI_HOST_BLOCK_SECONDS_403 = 900.0
CTI_HOST_BLOCK_SECONDS_429 = 3600.0
CTI_HOST_BLOCK_SECONDS_TRANSPORT = 300.0
CTI_PAGE_MAX_BYTES = 250000
CTI_REQUEST_TIMEOUT = 20.0
CTI_DOWNLOAD_ALLOWLIST = (
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
)

# AlienVault OTX (API key: OTX_API_KEY in secrets section above)
OTX_ENABLED = True
OTX_PULSE_DAYS = 7
OTX_PULSE_LIMIT = 10
OTX_PULSE_MAX_HASHES = 30

# Ollama model behavior
OLLAMA_TIMEOUT = 8.0
REPORT_LANGUAGE = "English"

# Benign PE sources
SYSINTERNALS_BASE_URLS = (
    "https://live.sysinternals.com/",
    "https://live.sysinternals.com/tools/",
)
GITHUB_API_URL = "https://api.github.com"
GITHUB_BENIGN_REPOS: list[tuple[str, str]] = [
    ("notepad-plus-plus", "notepad-plus-plus"),
    ("ShareX", "ShareX"),
    ("git-for-windows", "git"),
    ("microsoft", "PowerToys"),
]

# --- Static feature name tables (do not edit by hand) ---

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

_SCALAR_FEATURE_NAMES = [
    "dos_header_size",
    "pe_header_offset",
    "rich_header_present",
    "rich_entropy",
    "num_sections",
    "avg_section_entropy",
    "max_section_entropy",
    "min_section_entropy",
    "std_section_entropy",
    "num_imported_dlls",
    "num_imported_apis",
    "has_exec_apis",
    "num_exports",
    "image_size",
    "entry_point",
    "subsystem",
    "dll_characteristics",
    "timestamp",
    "file_size",
    "overlay_size",
    "has_overlay",
    "string_count",
    "avg_string_length",
    "max_string_length",
    "printable_char_count",
    "url_count",
    "path_count",
    "registry_key_count",
    "mz_marker_count",
    "coff_machine",
    "coff_number_of_sections",
    "coff_time_date_stamp",
    "coff_pointer_to_symbol_table",
    "coff_number_of_symbols",
    "coff_size_of_optional_header",
    "coff_characteristics",
    "optional_magic",
    "major_linker_version",
    "minor_linker_version",
    "size_of_code",
    "size_of_initialized_data",
    "size_of_uninitialized_data",
    "base_of_code",
    "base_of_data",
    "image_base",
    "section_alignment",
    "file_alignment",
    "major_os_version",
    "minor_os_version",
    "major_image_version",
    "minor_image_version",
    "major_subsystem_version",
    "minor_subsystem_version",
    "win32_version_value",
    "size_of_headers",
    "checksum",
    "size_of_stack_reserve",
    "size_of_stack_commit",
    "size_of_heap_reserve",
    "size_of_heap_commit",
    "loader_flags",
    "number_of_rva_and_sizes",
    "has_authenticode",
    "authenticode_size",
    "parse_warning_count",
    "section_raw_size_total",
    "section_virtual_size_total",
    "section_exec_count",
    "section_write_count",
    "section_read_count",
    "section_zero_raw_count",
    "section_zero_virtual_count",
    "section_suspicious_name_count",
    "section_name_entropy",
    "capstone_available",
    "disassembled_instruction_count",
    "branch_instruction_count",
    "call_instruction_count",
    "ret_instruction_count",
    "indirect_branch_count",
    "memory_operand_instruction_count",
    "immediate_operand_instruction_count",
]
_SCALAR_FEATURE_NAMES += [f"data_directory_{i:02d}_rva" for i in range(16)]
_SCALAR_FEATURE_NAMES += [f"data_directory_{i:02d}_size" for i in range(16)]
_SCALAR_FEATURE_NAMES += [
    f"scalar_reserved_{i:03d}"
    for i in range(128 - len(_SCALAR_FEATURE_NAMES))
]

BYTE_HIST_FEATURE_NAMES = [f"byte_hist_{i:03d}" for i in range(256)]
BYTE_ENTROPY_FEATURE_NAMES = [
    f"byte_entropy_{entropy_bin:02d}_{byte_bin:02d}"
    for entropy_bin in range(16)
    for byte_bin in range(16)
]
PRINTABLE_FEATURE_NAMES = [f"printable_{i:03d}" for i in range(96)]
IMPORT_HASH_FEATURE_NAMES = [f"import_hash_{i:04d}" for i in range(1024)]
EXPORT_HASH_FEATURE_NAMES = [f"export_hash_{i:03d}" for i in range(256)]
SECTION_HASH_FEATURE_NAMES = [f"section_hash_{i:03d}" for i in range(128)]
OPCODE_FEATURE_NAMES = [f"opcode_feature_{i:03d}" for i in range(160)]

FEATURE_NAMES = (
    _SCALAR_FEATURE_NAMES
    + BYTE_HIST_FEATURE_NAMES
    + BYTE_ENTROPY_FEATURE_NAMES
    + PRINTABLE_FEATURE_NAMES
    + IMPORT_HASH_FEATURE_NAMES
    + EXPORT_HASH_FEATURE_NAMES
    + SECTION_HASH_FEATURE_NAMES
    + OPCODE_FEATURE_NAMES
)

if len(FEATURE_NAMES) != FEATURE_DIM:
    raise RuntimeError(f"FEATURE_NAMES length {len(FEATURE_NAMES)} != FEATURE_DIM {FEATURE_DIM}")

# --- Helpers ---


def ensure_dirs() -> None:
    """Create required directories."""
    for path in (
        SANDBOX_DIR,
        DB_PATH.parent,
        MODEL_PATH.parent,
        BENIGN_DIR,
        FIGURES_DIR,
        EVAL_STATE_PATH.parent,
        DRIFT_LOG_PATH.parent,
        LOG_PATH.parent,
        REPOS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def get_auth_key() -> str:
    key = os.getenv("MALWAREBAZAAR_AUTH_KEY", "")
    if not key:
        raise ValueError("Missing MALWAREBAZAAR_AUTH_KEY environment variable")
    return key


def get_github_token() -> str:
    return os.getenv("GITHUB_TOKEN", "").strip()


def get_malshare_api_key() -> str:
    key = os.getenv("MALSHARE_API_KEY", "").strip()
    if not key:
        raise ValueError("Missing MALSHARE_API_KEY environment variable")
    return key


def allow_local_benign() -> bool:
    return ALLOW_LOCAL_BENIGN


def malshare_enabled() -> bool:
    return MALSHARE_ENABLED


def mb_fallback_malshare() -> bool:
    return MB_FALLBACK_MALSHARE


def pe_source_discovery_enabled() -> bool:
    return PE_SOURCE_DISCOVERY_ENABLED


def ollama_source_selection_enabled() -> bool:
    return OLLAMA_SOURCE_SELECTION_ENABLED

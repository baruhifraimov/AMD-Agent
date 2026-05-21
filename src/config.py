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
PE_FETCH_LIMIT_ENV = "AMD_PE_FETCH_LIMIT"
PE_FETCH_LIMIT = int(os.getenv(PE_FETCH_LIMIT_ENV, "10"))
TARGET_FPR = 0.001
FEATURE_SET_VERSION = "ember_static_v1"
FEATURE_DIM = 2304

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
CTI_SEARCH_BACKENDS_ENV = "AMD_CTI_SEARCH_BACKENDS"
BRAVE_SEARCH_API_KEY_ENV = "AMD_BRAVE_SEARCH_API_KEY"
MALWARE_FALLBACK_PROVIDERS_ENV = "AMD_MALWARE_FALLBACK_PROVIDERS"
FALLBACK_PE_CHECK_MULT_ENV = "AMD_FALLBACK_PE_CHECK_MULT"
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
ADWIN_DELTA_ENV = "AMD_ADWIN_DELTA"
FEATURE_SELECTION_K_ENV = "AMD_FEATURE_SELECTION_K"
OPTUNA_TRIALS_ENV = "AMD_OPTUNA_TRIALS"
OPTUNA_TIMEOUT_ENV = "AMD_OPTUNA_TIMEOUT"
DRIFT_WINDOW_DAYS_ENV = "AMD_DRIFT_WINDOW_DAYS"
DRIFT_MIN_WINDOW_SAMPLES_ENV = "AMD_DRIFT_MIN_WINDOW_SAMPLES"
REPLAY_FRACTION_ENV = "AMD_REPLAY_FRACTION"
MB_CIRCUIT_FAILURE_THRESHOLD_ENV = "AMD_MB_CIRCUIT_FAILURE_THRESHOLD"
MB_CIRCUIT_OPEN_SECONDS_ENV = "AMD_MB_CIRCUIT_OPEN_SECONDS"
CTI_HOST_BLOCK_SECONDS_403_ENV = "AMD_CTI_HOST_BLOCK_SECONDS_403"
CTI_HOST_BLOCK_SECONDS_429_ENV = "AMD_CTI_HOST_BLOCK_SECONDS_429"
CTI_HOST_BLOCK_SECONDS_TRANSPORT_ENV = "AMD_CTI_HOST_BLOCK_SECONDS_TRANSPORT"


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
ADWIN_DELTA = float(os.getenv(ADWIN_DELTA_ENV, "0.002"))
FEATURE_SELECTION_K = int(os.getenv(FEATURE_SELECTION_K_ENV, "384"))
OPTUNA_TRIALS = int(os.getenv(OPTUNA_TRIALS_ENV, "25"))
OPTUNA_TIMEOUT = int(os.getenv(OPTUNA_TIMEOUT_ENV, "300"))
DRIFT_WINDOW_DAYS = int(os.getenv(DRIFT_WINDOW_DAYS_ENV, "60"))
DRIFT_MIN_WINDOW_SAMPLES = int(os.getenv(DRIFT_MIN_WINDOW_SAMPLES_ENV, "50"))
REPLAY_FRACTION = float(os.getenv(REPLAY_FRACTION_ENV, "0.3"))
MB_CIRCUIT_FAILURE_THRESHOLD = int(os.getenv(MB_CIRCUIT_FAILURE_THRESHOLD_ENV, "3"))
MB_CIRCUIT_OPEN_SECONDS = float(os.getenv(MB_CIRCUIT_OPEN_SECONDS_ENV, "120"))
CTI_HOST_BLOCK_SECONDS_403 = float(os.getenv(CTI_HOST_BLOCK_SECONDS_403_ENV, "900"))
CTI_HOST_BLOCK_SECONDS_429 = float(os.getenv(CTI_HOST_BLOCK_SECONDS_429_ENV, "3600"))
CTI_HOST_BLOCK_SECONDS_TRANSPORT = float(
    os.getenv(CTI_HOST_BLOCK_SECONDS_TRANSPORT_ENV, "300")
)
_raw_malware_fallbacks = os.getenv(MALWARE_FALLBACK_PROVIDERS_ENV)
MALWARE_FALLBACK_PROVIDERS = tuple(
    p.strip().lower()
    for p in (
        _raw_malware_fallbacks
        if _raw_malware_fallbacks is not None
        else "threatfox,twitter,dynamic_cti"
    ).split(",")
    if p.strip()
)
FALLBACK_PE_CHECK_MULT = max(1, int(os.getenv(FALLBACK_PE_CHECK_MULT_ENV, "1")))

# Dynamic CTI discovery limits
CTI_SEARCH_LIMIT = int(os.getenv("AMD_CTI_SEARCH_LIMIT", "5"))
CTI_SEARCH_BACKENDS = os.getenv(CTI_SEARCH_BACKENDS_ENV, "duckduckgo").strip() or "duckduckgo"
BRAVE_SEARCH_API_KEY = os.getenv(BRAVE_SEARCH_API_KEY_ENV, "").strip()
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

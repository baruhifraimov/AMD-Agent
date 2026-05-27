"""Scheduler, logging, feature flags, and collection tuning."""

# --- Scheduler and bootstrap ---
# Daemon: `python -m src.graph --daemon`
# Bootstrap: `python -m src.graph --bootstrap`

SCHED_ENABLED = False
SCHED_INTERVAL_SECONDS = 300
SCHED_MAX_RUNS: int | None = None
SCHED_RUN_ON_START = True
SCHED_JITTER_SECONDS = 30
SCHED_ERROR_BACKOFF_SECONDS = 60
SCHED_MAX_BACKOFF_SECONDS = 600

BOOTSTRAP_MAX_RUNS = 60
BOOTSTRAP_INTERVAL_SECONDS = 10

# --- Logging ---

VERBOSE = True  # True = detailed per-item console logs (file always full detail)
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

# Ollama request/response trace (full payloads always in amd-agent.log)
OLLAMA_LOG_DETAIL = True
OLLAMA_LOG_MAX_CHARS = 80000
OLLAMA_LOG_CONSOLE_PREVIEW = 500000

# --- Feature flags (providers, Ollama, local benign) ---

ALLOW_LOCAL_BENIGN = True
MALSHARE_ENABLED = True
MB_FALLBACK_MALSHARE = True
PE_SOURCE_DISCOVERY_ENABLED = False
CTI_SEED_SOURCES_ENABLED = True
OLLAMA_ENABLED = True
OLLAMA_SOURCE_SELECTION_ENABLED = True
OLLAMA_DRIFT_CONTEXT_REPORT_ENABLED = True
FORCED_BENIGN_PROVIDER: str | None = None

# --- Semantic hash filter (Ollama-assisted CTI) ---

SEMANTIC_MIN_CONFIDENCE = 0.6
SEMANTIC_REQUIRE_TECHNICAL_REPORT = False

# --- Collection balance and provider discovery ---

TARGET_MALWARE_BENIGN_RATIO = 1.0
BENIGN_PROVIDER_NAMES = ("sysinternals", "github", "benign_net")
IMBALANCE_ALERT_RATIO = 0.5

MALWARE_FALLBACK_PROVIDERS = ("malshare", "threatfox", "otx_pulse_cti")
FALLBACK_PE_CHECK_MULT = 5
PE_DOWNLOAD_MAX_BYTES = 250000
BENIGN_NET_REPO_URL = "https://github.com/bormaa/Benign-NET.git"
PE_DISCOVERY_MAX_URLS = 8
MIN_PE_SOURCES = 3

# --- Threat intel polling and provider cooldown ---

INTEL_MIN_POLL_INTERVAL = 60
INTEL_MAX_POLL_INTERVAL = 3600
PROVIDER_COOLDOWN_ZERO_RUNS = 3
PROVIDER_COOLDOWN_SECONDS = 43200
PROVIDER_COOLDOWN_MIN_ATTEMPTS = 5
STEADY_BENIGN_EVERY_N = 4

# --- Reports ---

REPORT_LANGUAGE = "English"

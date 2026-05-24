"""External API endpoints, rate limits, and circuit breaker settings."""

from src.pe.profile import PE_TAG_QUERIES

# --- MalwareBazaar (abuse.ch; Auth-Key via get_auth_key()) ---

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
# abuse.ch fair-use: ~2,000 get_file downloads per IP/day
MB_DAILY_DOWNLOAD_LIMIT = 1900
MB_MAX_INFO_CALLS_PER_RUN = 50
# get_file_type is often slow/502 upstream; get_recent is the reliable PE path
MB_USE_GET_FILE_TYPE_QUERY = False
MB_GET_FILE_TYPE_TIMEOUT = 15.0

# --- ThreatFox (same Auth-Key as MalwareBazaar) ---

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
TF_MIN_REQUEST_INTERVAL = 1.0
TF_GET_IOCS_TIMEOUT = 120.0
TF_GET_IOCS_DAYS_DEFAULT = 1
TF_CIRCUIT_FAILURE_THRESHOLD = 3
TF_CIRCUIT_OPEN_SECONDS = 120.0
TF_CIRCUIT_OPEN_SECONDS_429 = 3600.0
TF_USER_AGENT = (
    "AMD-Agent/1.0 (malware-ml-research; contact via MALWAREBAZAAR_AUTH_KEY holder)"
)
THREATFOX_DISCOVERY_SCAN_MULT = 20
# Fallback when get_iocs payload is truncated
THREATFOX_TAG_QUERIES = PE_TAG_QUERIES
THREATFOX_TAGINFO_LIMIT = 100

# --- CTI web fetch (host blocks, page limits) ---

CTI_HOST_BLOCK_SECONDS_403 = 900.0
CTI_HOST_BLOCK_SECONDS_429 = 3600.0
CTI_HOST_BLOCK_SECONDS_TRANSPORT = 300.0
CTI_PAGE_MAX_BYTES = 250000
CTI_REQUEST_TIMEOUT = 20.0

# --- AlienVault OTX (API key: OTX_API_KEY in secrets) ---

OTX_ENABLED = True
OTX_PULSE_DAYS = 7
OTX_PULSE_LIMIT = 10
OTX_PULSE_MAX_HASHES = 30
OTX_SKIP_SEMANTIC_FILTER_BOOTSTRAP = True

# --- Ollama and GitHub API ---

OLLAMA_TIMEOUT = 8.0
GITHUB_API_URL = "https://api.github.com"

"""Static external source inventories (URLs, repos, download allowlists)."""

# --- Benign PE sources (Sysinternals live directory) ---

SYSINTERNALS_BASE_URLS = (
    "https://live.sysinternals.com/",
    "https://live.sysinternals.com/tools/",
)

# --- Benign PE sources (GitHub releases; owner/repo tuples) ---

GITHUB_BENIGN_REPOS: list[tuple[str, str]] = [
    ("notepad-plus-plus", "notepad-plus-plus"),
    ("ShareX", "ShareX"),
    ("git-for-windows", "git"),
    ("microsoft", "PowerToys"),
]

# --- CTI download allowlist (hosts permitted for PE URL extraction) ---

CTI_DOWNLOAD_ALLOWLIST = (
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
)

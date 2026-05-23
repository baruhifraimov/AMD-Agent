"""URL quality filters for intel source polling."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from src.intel.rss import is_valid_feed_url
from src.tools.cti_search import is_public_url

LOW_SIGNAL_PATH_RE = re.compile(
    r"(manualpe|malware-detection-pe-files|static-pe-malware-analysis|"
    r"pe-structure|reverse-engineering|/abs/|/paper|/article)",
    re.I,
)
LOW_SIGNAL_CTI_HOSTS = (
    "acmrvce.com",
    "arxiv.org",
    "coursehero.com",
    "frontiersin.org",
    "github.com",
    "link.springer.com",
    "medium.com",
    "mendeley.com",
    "mdpi.com",
    "researchgate.net",
    "sciencedirect.com",
    "springer.com",
)


def is_low_signal_cti_url(url: str) -> bool:
    """Return True for hosts/pages that tend to be articles, tutorials, or papers."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if any(host == blocked or host.endswith(f".{blocked}") for blocked in LOW_SIGNAL_CTI_HOSTS):
        return True
    return bool(LOW_SIGNAL_PATH_RE.search(parsed.path or ""))


def is_precise_intel_source_url(url: str) -> bool:
    """Return True only for source URLs worth polling repeatedly."""
    if not is_public_url(url) or is_low_signal_cti_url(url):
        return False
    return is_valid_feed_url(url)

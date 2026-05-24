"""OOP HTTP clients for external malware/benign sample APIs."""

from src.tools.clients.http_client_base import ApiUnavailable, CircuitBreaker, HttpApiClient, RateLimiter
from src.tools.clients.malshare_api_client import MalShareClient, MalShareUnavailable
from src.pe.profile import is_pe_sample
from src.tools.clients.malwarebazaar_api_client import (
    MalwareBazaarClient,
    MalwareBazaarQuotaExceeded,
    MalwareBazaarUnavailable,
)
from src.tools.clients.threatfox_api_client import ThreatFoxClient

__all__ = [
    "ApiUnavailable",
    "CircuitBreaker",
    "HttpApiClient",
    "RateLimiter",
    "MalwareBazaarClient",
    "MalwareBazaarQuotaExceeded",
    "MalwareBazaarUnavailable",
    "MalShareClient",
    "MalShareUnavailable",
    "ThreatFoxClient",
    "is_pe_sample",
]

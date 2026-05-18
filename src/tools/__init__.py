"""Tool integrations for the agent."""

from src.tools.fetch import save_pe_to_sandbox
from src.tools.malwarebazaar import (
    download_sample,
    get_file_info,
    get_recent_pe,
    is_pe_hash,
    is_pe_sample,
)
from src.tools.validate import is_duplicate, is_pe_mz

__all__ = [
    "get_recent_pe",
    "download_sample",
    "get_file_info",
    "is_pe_hash",
    "is_pe_sample",
    "save_pe_to_sandbox",
    "is_pe_mz",
    "is_duplicate",
]

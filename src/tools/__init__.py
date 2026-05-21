"""Tool integrations for the agent."""

from src.tools.fetch import save_pe_to_sandbox
from src.tools.malwarebazaar import (
    download_sample,
    get_file_type,
    get_file_info,
    get_recent_pe,
    is_pe_hash,
    is_pe_sample,
)
from src.tools.update import (
    insert_pending_hash,
    insert_sample,
    mark_corrupted,
    update_features,
    update_file_path,
    update_prediction,
)
from src.tools.validate import file_sha256, is_duplicate, is_pe_mz, is_pe_signature

__all__ = [
    "get_recent_pe",
    "get_file_type",
    "download_sample",
    "get_file_info",
    "is_pe_hash",
    "is_pe_sample",
    "save_pe_to_sandbox",
    "file_sha256",
    "is_pe_mz",
    "is_pe_signature",
    "is_duplicate",
    "insert_sample",
    "update_file_path",
    "update_features",
    "update_prediction",
    "mark_corrupted",
    "insert_pending_hash",
]

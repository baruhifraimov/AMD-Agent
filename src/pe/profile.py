"""Windows PE taxonomy — shared metadata, tags, and path checks."""

from __future__ import annotations

from typing import Any

PE_MIME = "application/x-dosexec"
PE_MAGIKA = frozenset({"pebin", "pedll", "peexe"})
PE_CTI_ALIAS_TAGS = ("pe", "peexe", "pedll")

PE_FILE_TYPE_ORDER = (
    "exe",
    "dll",
    "sys",
    "scr",
    "cpl",
    "ocx",
    "drv",
    "efi",
    "acm",
    "ax",
    "mui",
    "tsp",
    "mun",
)
PE_FILE_EXTENSIONS = frozenset(PE_FILE_TYPE_ORDER)
PE_ARCHIVE_SUFFIXES = tuple(f".{ext}" for ext in PE_FILE_TYPE_ORDER)

# Extensions queried on ThreatFox (subset of PE_FILE_TYPE_ORDER, high-yield first).
_TAG_QUERY_EXTENSIONS = frozenset({"exe", "dll", "sys", "scr", "cpl", "ocx", "efi", "drv"})
PE_TAG_QUERIES = tuple(e for e in PE_FILE_TYPE_ORDER if e in _TAG_QUERY_EXTENSIONS) + PE_CTI_ALIAS_TAGS

# IOC tag matching: queried tags plus any PE extension ThreatFox may attach.
PE_CTI_TAGS = frozenset(PE_TAG_QUERIES) | PE_FILE_EXTENSIONS

MAX_FILE_TYPE_LIMIT = 1000


def is_pe_metadata(meta: dict[str, Any]) -> bool:
    if (meta.get("file_type_mime") or "").lower() == PE_MIME:
        return True
    if (meta.get("magika") or "").lower() in PE_MAGIKA:
        return True
    return (meta.get("file_type") or "").lower() in PE_FILE_EXTENSIONS


is_pe_sample = is_pe_metadata


def has_pe_extension(name_or_path: str) -> bool:
    lower = name_or_path.strip().lower()
    return bool(lower) and lower.endswith(PE_ARCHIVE_SUFFIXES)

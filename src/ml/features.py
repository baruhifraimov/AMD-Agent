"""Static PE feature extraction via pefile."""

from __future__ import annotations

import logging
import math
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pefile

from src.config import EXEC_API_NAMES, FEATURE_NAMES

logger = logging.getLogger(__name__)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_pe_features(path: str | Path) -> dict[str, Any] | None:
    """Extract 15 structural PE features. Returns None on parse failure."""
    path = Path(path)
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ]
        )
    except Exception as exc:
        logger.warning("pefile parse failed for %s: %s", path, exc)
        return None

    try:
        dos_header_size = int(pe.DOS_HEADER.e_cblp)
        pe_header_offset = int(pe.DOS_HEADER.e_lfanew)

        rich_present = 0.0
        rich_entropy = 0.0
        rich = getattr(pe, "RichHeader", None)
        if rich is not None and getattr(rich, "data", None):
            rich_present = 1.0
            rich_entropy = _shannon_entropy(bytes(rich.data))

        sections = pe.sections or []
        num_sections = float(len(sections))
        entropies = []
        for section in sections:
            data = section.get_data()
            entropies.append(_shannon_entropy(data))
        avg_section_entropy = float(np.mean(entropies)) if entropies else 0.0
        max_section_entropy = float(max(entropies)) if entropies else 0.0

        dlls = set()
        api_count = 0
        exec_api = 0.0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore").lower()
                dlls.add(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        api_count += 1
                        name = imp.name.decode(errors="ignore")
                        if name in EXEC_API_NAMES:
                            exec_api = 1.0

        optional = pe.OPTIONAL_HEADER
        features = {
            "dos_header_size": float(dos_header_size),
            "pe_header_offset": float(pe_header_offset),
            "rich_header_present": rich_present,
            "rich_entropy": rich_entropy,
            "num_sections": num_sections,
            "avg_section_entropy": avg_section_entropy,
            "max_section_entropy": max_section_entropy,
            "num_imported_dlls": float(len(dlls)),
            "num_imported_apis": float(api_count),
            "has_exec_apis": exec_api,
            "image_size": float(optional.SizeOfImage),
            "entry_point": float(optional.AddressOfEntryPoint),
            "subsystem": float(optional.Subsystem),
            "dll_characteristics": float(optional.DllCharacteristics),
            "timestamp": float(optional.TimeDateStamp),
            "sha256": path.stem if len(path.stem) == 64 else "",
        }
        pe.close()
        return features
    except Exception as exc:
        logger.warning("feature extraction failed for %s: %s", path, exc)
        try:
            pe.close()
        except Exception:
            pass
        return None


def features_to_vector(features: dict[str, Any]) -> np.ndarray:
    """Convert feature dict to fixed-order numeric vector."""
    return np.array([float(features.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float64)


def vectorize_batch(feature_dicts: list[dict[str, Any]]) -> np.ndarray:
    if not feature_dicts:
        return np.empty((0, len(FEATURE_NAMES)))
    return np.vstack([features_to_vector(d) for d in feature_dicts])

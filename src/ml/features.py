"""EMBER-like static PE feature extraction."""

from __future__ import annotations

import hashlib
import math
import mmap
import re
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pefile

from src.config import (
    BYTE_ENTROPY_FEATURE_NAMES,
    BYTE_HIST_FEATURE_NAMES,
    EXEC_API_NAMES,
    EXPORT_HASH_FEATURE_NAMES,
    FEATURE_DIM,
    FEATURE_NAMES,
    FEATURE_SET_VERSION,
    IMPORT_HASH_FEATURE_NAMES,
    OPCODE_FEATURE_NAMES,
    PRINTABLE_FEATURE_NAMES,
    SECTION_HASH_FEATURE_NAMES,
)

from src.log import PHASE_EXTRACTION, get_logger, phase_log, vlog

logger = get_logger(__name__)

try:  # Optional at runtime until Docker image is rebuilt.
    import capstone
except Exception:  # pragma: no cover - exercised in old local environments.
    capstone = None

_ASCII_STRING_RE = re.compile(rb"[\x20-\x7E]{4,}")
_URL_RE = re.compile(rb"https?://|www\.", re.IGNORECASE)
_PATH_RE = re.compile(rb"[a-zA-Z]:\\|\\\\[a-zA-Z0-9_.-]+\\")
_REGISTRY_RE = re.compile(rb"HKEY_|HKLM\\|HKCU\\|Software\\Microsoft", re.IGNORECASE)
_SUSPICIOUS_SECTION_NAMES = {".packed", ".upx", "upx0", "upx1", ".aspack", ".vmp", ".themida"}


def extract_string_metrics(file_bytes: bytes) -> tuple[int, float]:
    """Count ASCII strings (len>=4) and average length on raw file bytes."""
    matches = _ASCII_STRING_RE.findall(file_bytes)
    if not matches:
        return 0, 0.0
    lengths = [len(m) for m in matches]
    return len(matches), float(sum(lengths) / len(lengths))


def _read_file_bytes(path: Path) -> bytes:
    with path.open("rb") as handle:
        try:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                return mapped[:]
        except (OSError, ValueError):
            handle.seek(0)
            return handle.read()


def _empty_features() -> dict[str, float | str]:
    features: dict[str, float | str] = {name: 0.0 for name in FEATURE_NAMES}
    features["_feature_set_version"] = FEATURE_SET_VERSION
    features["_feature_dim"] = float(FEATURE_DIM)
    return features


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(int(value))
    except Exception:
        try:
            return float(value)
        except Exception:
            return default


def _stable_hash(text: str, modulo: int) -> int:
    digest = hashlib.blake2b(text.encode("utf-8", errors="ignore"), digest_size=8).digest()
    return int.from_bytes(digest, "little") % modulo


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _entropy_from_counts(counts: np.ndarray, length: int) -> float:
    if length <= 0:
        return 0.0
    probs = counts[counts > 0].astype(np.float64) / float(length)
    return float(-np.sum(probs * np.log2(probs)))


def _add_byte_histogram(features: dict[str, float | str], file_bytes: bytes) -> None:
    if not file_bytes:
        return
    arr = np.frombuffer(file_bytes, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256).astype(np.float64)
    counts /= max(float(counts.sum()), 1.0)
    for name, value in zip(BYTE_HIST_FEATURE_NAMES, counts):
        features[name] = float(value)


def _add_byte_entropy_histogram(
    features: dict[str, float | str],
    file_bytes: bytes,
    *,
    window_size: int = 2048,
) -> None:
    if not file_bytes:
        return
    hist = np.zeros((16, 16), dtype=np.float64)
    arr = np.frombuffer(file_bytes, dtype=np.uint8)
    for start in range(0, len(arr), window_size):
        chunk = arr[start : start + window_size]
        if len(chunk) == 0:
            continue
        byte_counts = np.bincount(chunk, minlength=256)
        entropy_bin = min(15, int((_entropy_from_counts(byte_counts, len(chunk)) / 8.0) * 16.0))
        high_nibble_counts = np.bincount(chunk >> 4, minlength=16)
        hist[entropy_bin, :] += high_nibble_counts
    total = float(hist.sum())
    if total > 0:
        hist /= total
    for name, value in zip(BYTE_ENTROPY_FEATURE_NAMES, hist.reshape(-1)):
        features[name] = float(value)


def _add_string_features(features: dict[str, float | str], file_bytes: bytes) -> None:
    matches = _ASCII_STRING_RE.findall(file_bytes)
    lengths = [len(match) for match in matches]
    features["string_count"] = float(len(matches))
    features["avg_string_length"] = float(sum(lengths) / len(lengths)) if lengths else 0.0
    features["max_string_length"] = float(max(lengths)) if lengths else 0.0
    features["printable_char_count"] = float(sum(lengths))
    features["url_count"] = float(len(_URL_RE.findall(file_bytes)))
    features["path_count"] = float(len(_PATH_RE.findall(file_bytes)))
    features["registry_key_count"] = float(len(_REGISTRY_RE.findall(file_bytes)))
    features["mz_marker_count"] = float(file_bytes.count(b"MZ"))

    printable_counts = np.zeros(96, dtype=np.float64)
    for match in matches:
        for byte in match:
            if 32 <= byte <= 127:
                printable_counts[byte - 32] += 1.0
    total = float(printable_counts.sum())
    if total > 0:
        printable_counts /= total
    for name, value in zip(PRINTABLE_FEATURE_NAMES, printable_counts):
        features[name] = float(value)


def _section_name(section: Any) -> str:
    raw = getattr(section, "Name", b"")
    if isinstance(raw, bytes):
        return raw.rstrip(b"\x00").decode(errors="ignore").lower()
    return str(raw).strip().lower()


def _add_section_features(features: dict[str, float | str], pe: pefile.PE) -> list[bytes]:
    sections = list(getattr(pe, "sections", []) or [])
    entropies: list[float] = []
    executable_blobs: list[bytes] = []
    name_blob = bytearray()
    raw_total = 0.0
    virtual_total = 0.0
    exec_count = write_count = read_count = 0
    zero_raw_count = zero_virtual_count = 0
    suspicious_count = 0

    for section in sections:
        name = _section_name(section)
        name_blob.extend(name.encode("utf-8", errors="ignore"))
        raw_size = _safe_float(getattr(section, "SizeOfRawData", 0))
        virtual_size = _safe_float(getattr(section, "Misc_VirtualSize", 0))
        characteristics = int(_safe_float(getattr(section, "Characteristics", 0)))
        data = section.get_data() if hasattr(section, "get_data") else b""
        entropy = _shannon_entropy(data)
        entropies.append(entropy)
        raw_total += raw_size
        virtual_total += virtual_size
        zero_raw_count += int(raw_size == 0)
        zero_virtual_count += int(virtual_size == 0)
        suspicious_count += int(name in _SUSPICIOUS_SECTION_NAMES)
        exec_flag = bool(characteristics & 0x20000000)
        read_count += int(bool(characteristics & 0x40000000))
        write_count += int(bool(characteristics & 0x80000000))
        exec_count += int(exec_flag)
        if exec_flag and data:
            executable_blobs.append(data)

        section_token = f"{name}:{characteristics:x}"
        idx = _stable_hash(section_token, len(SECTION_HASH_FEATURE_NAMES))
        features[SECTION_HASH_FEATURE_NAMES[idx]] = float(features[SECTION_HASH_FEATURE_NAMES[idx]]) + math.log1p(
            raw_size + virtual_size
        )

    features["num_sections"] = float(len(sections))
    features["avg_section_entropy"] = float(np.mean(entropies)) if entropies else 0.0
    features["max_section_entropy"] = float(max(entropies)) if entropies else 0.0
    features["min_section_entropy"] = float(min(entropies)) if entropies else 0.0
    features["std_section_entropy"] = float(np.std(entropies)) if entropies else 0.0
    features["section_raw_size_total"] = raw_total
    features["section_virtual_size_total"] = virtual_total
    features["section_exec_count"] = float(exec_count)
    features["section_write_count"] = float(write_count)
    features["section_read_count"] = float(read_count)
    features["section_zero_raw_count"] = float(zero_raw_count)
    features["section_zero_virtual_count"] = float(zero_virtual_count)
    features["section_suspicious_name_count"] = float(suspicious_count)
    features["section_name_entropy"] = _shannon_entropy(bytes(name_blob))
    return executable_blobs


def _add_header_features(features: dict[str, float | str], pe: pefile.PE, file_bytes: bytes) -> None:
    dos = getattr(pe, "DOS_HEADER", None)
    file_header = getattr(pe, "FILE_HEADER", None)
    optional = getattr(pe, "OPTIONAL_HEADER", None)

    features["dos_header_size"] = _safe_float(getattr(dos, "e_cblp", 0))
    features["pe_header_offset"] = _safe_float(getattr(dos, "e_lfanew", 0))
    rich = getattr(pe, "RichHeader", None)
    rich_data = getattr(rich, "data", None)
    if rich_data:
        features["rich_header_present"] = 1.0
        features["rich_entropy"] = _shannon_entropy(bytes(rich_data))

    for name, attr in {
        "coff_machine": "Machine",
        "coff_number_of_sections": "NumberOfSections",
        "coff_time_date_stamp": "TimeDateStamp",
        "coff_pointer_to_symbol_table": "PointerToSymbolTable",
        "coff_number_of_symbols": "NumberOfSymbols",
        "coff_size_of_optional_header": "SizeOfOptionalHeader",
        "coff_characteristics": "Characteristics",
    }.items():
        features[name] = _safe_float(getattr(file_header, attr, 0))
    features["timestamp"] = features["coff_time_date_stamp"]

    for name, attr in {
        "optional_magic": "Magic",
        "major_linker_version": "MajorLinkerVersion",
        "minor_linker_version": "MinorLinkerVersion",
        "size_of_code": "SizeOfCode",
        "size_of_initialized_data": "SizeOfInitializedData",
        "size_of_uninitialized_data": "SizeOfUninitializedData",
        "entry_point": "AddressOfEntryPoint",
        "base_of_code": "BaseOfCode",
        "base_of_data": "BaseOfData",
        "image_base": "ImageBase",
        "section_alignment": "SectionAlignment",
        "file_alignment": "FileAlignment",
        "major_os_version": "MajorOperatingSystemVersion",
        "minor_os_version": "MinorOperatingSystemVersion",
        "major_image_version": "MajorImageVersion",
        "minor_image_version": "MinorImageVersion",
        "major_subsystem_version": "MajorSubsystemVersion",
        "minor_subsystem_version": "MinorSubsystemVersion",
        "win32_version_value": "Win32VersionValue",
        "image_size": "SizeOfImage",
        "size_of_headers": "SizeOfHeaders",
        "checksum": "CheckSum",
        "subsystem": "Subsystem",
        "dll_characteristics": "DllCharacteristics",
        "size_of_stack_reserve": "SizeOfStackReserve",
        "size_of_stack_commit": "SizeOfStackCommit",
        "size_of_heap_reserve": "SizeOfHeapReserve",
        "size_of_heap_commit": "SizeOfHeapCommit",
        "loader_flags": "LoaderFlags",
        "number_of_rva_and_sizes": "NumberOfRvaAndSizes",
    }.items():
        features[name] = _safe_float(getattr(optional, attr, 0))

    data_directories = list(getattr(optional, "DATA_DIRECTORY", []) or [])
    for idx in range(16):
        directory = data_directories[idx] if idx < len(data_directories) else None
        features[f"data_directory_{idx:02d}_rva"] = _safe_float(
            getattr(directory, "VirtualAddress", 0)
        )
        features[f"data_directory_{idx:02d}_size"] = _safe_float(getattr(directory, "Size", 0))
    security_dir = data_directories[4] if len(data_directories) > 4 else None
    signature_size = _safe_float(getattr(security_dir, "Size", 0))
    features["has_authenticode"] = float(signature_size > 0)
    features["authenticode_size"] = signature_size

    features["file_size"] = float(len(file_bytes))
    overlay_offset = pe.get_overlay_data_start_offset() if hasattr(pe, "get_overlay_data_start_offset") else None
    if overlay_offset is not None:
        overlay_size = max(0, len(file_bytes) - int(overlay_offset))
        features["overlay_size"] = float(overlay_size)
        features["has_overlay"] = float(overlay_size > 0)
    try:
        features["parse_warning_count"] = float(len(pe.get_warnings()))
    except Exception:
        features["parse_warning_count"] = 0.0


def _add_import_export_features(features: dict[str, float | str], pe: pefile.PE) -> None:
    exec_names = {name.lower() for name in EXEC_API_NAMES}
    dlls: set[str] = set()
    api_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = bytes(getattr(entry, "dll", b"") or b"").decode(errors="ignore").lower()
            if dll_name:
                dlls.add(dll_name)
            for imp in getattr(entry, "imports", []) or []:
                raw_name = getattr(imp, "name", None)
                if raw_name:
                    name = bytes(raw_name).decode(errors="ignore").lower()
                else:
                    name = f"ordinal_{_safe_float(getattr(imp, 'ordinal', 0)):.0f}"
                api_count += 1
                if name in exec_names:
                    features["has_exec_apis"] = 1.0
                idx = _stable_hash(f"{dll_name}:{name}", len(IMPORT_HASH_FEATURE_NAMES))
                features[IMPORT_HASH_FEATURE_NAMES[idx]] = float(features[IMPORT_HASH_FEATURE_NAMES[idx]]) + 1.0
    features["num_imported_dlls"] = float(len(dlls))
    features["num_imported_apis"] = float(api_count)

    export_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for symbol in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []) or []:
            raw_name = getattr(symbol, "name", None)
            if raw_name:
                name = bytes(raw_name).decode(errors="ignore").lower()
            else:
                name = f"ordinal_{_safe_float(getattr(symbol, 'ordinal', 0)):.0f}"
            export_count += 1
            idx = _stable_hash(name, len(EXPORT_HASH_FEATURE_NAMES))
            features[EXPORT_HASH_FEATURE_NAMES[idx]] = float(features[EXPORT_HASH_FEATURE_NAMES[idx]]) + 1.0
    features["num_exports"] = float(export_count)

    for name in IMPORT_HASH_FEATURE_NAMES + EXPORT_HASH_FEATURE_NAMES:
        features[name] = math.log1p(float(features[name]))


def _add_instruction_features(
    features: dict[str, float | str],
    pe: pefile.PE,
    executable_blobs: list[bytes],
    *,
    max_code_bytes: int = 65536,
) -> None:
    if capstone is None or not executable_blobs:
        return
    machine = int(_safe_float(getattr(getattr(pe, "FILE_HEADER", None), "Machine", 0)))
    mode = capstone.CS_MODE_64 if machine == 0x8664 else capstone.CS_MODE_32
    try:
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, mode)
        disassembler.detail = False
    except Exception:
        return

    features["capstone_available"] = 1.0
    opcode_values = np.zeros(160, dtype=np.float64)
    previous = ""
    seen_bytes = 0
    instruction_count = 0
    branch_count = call_count = ret_count = indirect_count = memory_count = immediate_count = 0
    for blob in executable_blobs:
        if seen_bytes >= max_code_bytes:
            break
        code = blob[: max_code_bytes - seen_bytes]
        seen_bytes += len(code)
        for insn in disassembler.disasm(code, 0):
            mnemonic = insn.mnemonic.lower()
            op_str = insn.op_str.lower()
            instruction_count += 1
            opcode_values[_stable_hash(mnemonic, 96)] += 1.0
            if previous:
                opcode_values[96 + _stable_hash(f"{previous}:{mnemonic}", 48)] += 1.0
            previous = mnemonic
            is_branch = mnemonic.startswith("j")
            branch_count += int(is_branch)
            call_count += int(mnemonic == "call")
            ret_count += int(mnemonic.startswith("ret"))
            indirect_count += int(is_branch and ("[" in op_str or "*" in op_str))
            memory_count += int("[" in op_str and "]" in op_str)
            immediate_count += int("0x" in op_str or any(char.isdigit() for char in op_str))

    if instruction_count <= 0:
        return
    opcode_values[:96] /= float(instruction_count)
    if instruction_count > 1:
        opcode_values[96:144] /= float(instruction_count - 1)
    scalar_counts = np.array(
        [
            branch_count,
            call_count,
            ret_count,
            indirect_count,
            memory_count,
            immediate_count,
            instruction_count,
        ],
        dtype=np.float64,
    )
    opcode_values[144 : 144 + len(scalar_counts)] = scalar_counts / float(instruction_count)

    for name, value in zip(OPCODE_FEATURE_NAMES, opcode_values):
        features[name] = float(value)
    features["disassembled_instruction_count"] = float(instruction_count)
    features["branch_instruction_count"] = float(branch_count)
    features["call_instruction_count"] = float(call_count)
    features["ret_instruction_count"] = float(ret_count)
    features["indirect_branch_count"] = float(indirect_count)
    features["memory_operand_instruction_count"] = float(memory_count)
    features["immediate_operand_instruction_count"] = float(immediate_count)


def extract_pe_features(path: str | Path) -> dict[str, Any] | None:
    """Extract static PE features. Returns None on parse failure."""
    features, _ = extract_pe_features_with_error(path)
    return features


def extract_pe_features_with_error(path: str | Path) -> tuple[dict[str, Any] | None, str | None]:
    """Extract a deterministic 2304-dimensional static PE feature dictionary."""
    path = Path(path)
    try:
        file_bytes = _read_file_bytes(path)
    except OSError as exc:
        logger.warning("[%s] failed to read %s: %s", PHASE_EXTRACTION, path, exc)
        return None, str(exc)

    features = _empty_features()
    _add_byte_histogram(features, file_bytes)
    _add_byte_entropy_histogram(features, file_bytes)
    _add_string_features(features, file_bytes)

    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        directories = [
            pefile.DIRECTORY_ENTRY[name]
            for name in (
                "IMAGE_DIRECTORY_ENTRY_IMPORT",
                "IMAGE_DIRECTORY_ENTRY_EXPORT",
                "IMAGE_DIRECTORY_ENTRY_SECURITY",
            )
            if name in pefile.DIRECTORY_ENTRY
        ]
        pe.parse_data_directories(directories=directories)
    except Exception as exc:
        logger.warning("[%s] pefile parse failed for %s: %s", PHASE_EXTRACTION, path, exc)
        return None, str(exc)

    try:
        _add_header_features(features, pe, file_bytes)
        executable_blobs = _add_section_features(features, pe)
        _add_import_export_features(features, pe)
        _add_instruction_features(features, pe, executable_blobs)
        features["sha256"] = path.stem if len(path.stem) == 64 else ""
        return features, None
    except Exception as exc:
        logger.warning("[%s] feature extraction failed for %s: %s", PHASE_EXTRACTION, path, exc)
        return None, str(exc)
    finally:
        try:
            pe.close()
        except Exception:
            pass


def features_to_vector(features: dict[str, Any]) -> np.ndarray:
    """Convert feature dict to fixed-order numeric vector."""
    return np.array([float(features.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float64)


def vectorize_batch(feature_dicts: list[dict[str, Any]]) -> np.ndarray:
    if not feature_dicts:
        return np.empty((0, len(FEATURE_NAMES)))
    return np.vstack([features_to_vector(d) for d in feature_dicts])

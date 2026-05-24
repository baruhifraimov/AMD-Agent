"""2304-d static feature name tables (EMBER-like schema).

Do not edit name lists by hand except EXEC_API_NAMES; counts must match FEATURE_DIM.
"""

from src.config.ml_settings import FEATURE_DIM

# --- Import API names used for has_exec_apis scalar ---

EXEC_API_NAMES = frozenset(
    {
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
        "RtlCreateUserThread",
    }
)

# --- Scalar PE header / section / capstone features (128 slots) ---

_SCALAR_FEATURE_NAMES = [
    "dos_header_size",
    "pe_header_offset",
    "rich_header_present",
    "rich_entropy",
    "num_sections",
    "avg_section_entropy",
    "max_section_entropy",
    "min_section_entropy",
    "std_section_entropy",
    "num_imported_dlls",
    "num_imported_apis",
    "has_exec_apis",
    "num_exports",
    "image_size",
    "entry_point",
    "subsystem",
    "dll_characteristics",
    "timestamp",
    "file_size",
    "overlay_size",
    "has_overlay",
    "string_count",
    "avg_string_length",
    "max_string_length",
    "printable_char_count",
    "url_count",
    "path_count",
    "registry_key_count",
    "mz_marker_count",
    "coff_machine",
    "coff_number_of_sections",
    "coff_time_date_stamp",
    "coff_pointer_to_symbol_table",
    "coff_number_of_symbols",
    "coff_size_of_optional_header",
    "coff_characteristics",
    "optional_magic",
    "major_linker_version",
    "minor_linker_version",
    "size_of_code",
    "size_of_initialized_data",
    "size_of_uninitialized_data",
    "base_of_code",
    "base_of_data",
    "image_base",
    "section_alignment",
    "file_alignment",
    "major_os_version",
    "minor_os_version",
    "major_image_version",
    "minor_image_version",
    "major_subsystem_version",
    "minor_subsystem_version",
    "win32_version_value",
    "size_of_headers",
    "checksum",
    "size_of_stack_reserve",
    "size_of_stack_commit",
    "size_of_heap_reserve",
    "size_of_heap_commit",
    "loader_flags",
    "number_of_rva_and_sizes",
    "has_authenticode",
    "authenticode_size",
    "parse_warning_count",
    "section_raw_size_total",
    "section_virtual_size_total",
    "section_exec_count",
    "section_write_count",
    "section_read_count",
    "section_zero_raw_count",
    "section_zero_virtual_count",
    "section_suspicious_name_count",
    "section_name_entropy",
    "capstone_available",
    "disassembled_instruction_count",
    "branch_instruction_count",
    "call_instruction_count",
    "ret_instruction_count",
    "indirect_branch_count",
    "memory_operand_instruction_count",
    "immediate_operand_instruction_count",
]
_SCALAR_FEATURE_NAMES += [f"data_directory_{i:02d}_rva" for i in range(16)]
_SCALAR_FEATURE_NAMES += [f"data_directory_{i:02d}_size" for i in range(16)]
_SCALAR_FEATURE_NAMES += [
    f"scalar_reserved_{i:03d}"
    for i in range(128 - len(_SCALAR_FEATURE_NAMES))
]

# --- Histogram and hashed feature blocks (2176 slots) ---

BYTE_HIST_FEATURE_NAMES = [f"byte_hist_{i:03d}" for i in range(256)]
BYTE_ENTROPY_FEATURE_NAMES = [
    f"byte_entropy_{entropy_bin:02d}_{byte_bin:02d}"
    for entropy_bin in range(16)
    for byte_bin in range(16)
]
PRINTABLE_FEATURE_NAMES = [f"printable_{i:03d}" for i in range(96)]
IMPORT_HASH_FEATURE_NAMES = [f"import_hash_{i:04d}" for i in range(1024)]
EXPORT_HASH_FEATURE_NAMES = [f"export_hash_{i:03d}" for i in range(256)]
SECTION_HASH_FEATURE_NAMES = [f"section_hash_{i:03d}" for i in range(128)]
OPCODE_FEATURE_NAMES = [f"opcode_feature_{i:03d}" for i in range(160)]

# --- Full vector (must equal FEATURE_DIM) ---

FEATURE_NAMES = (
    _SCALAR_FEATURE_NAMES
    + BYTE_HIST_FEATURE_NAMES
    + BYTE_ENTROPY_FEATURE_NAMES
    + PRINTABLE_FEATURE_NAMES
    + IMPORT_HASH_FEATURE_NAMES
    + EXPORT_HASH_FEATURE_NAMES
    + SECTION_HASH_FEATURE_NAMES
    + OPCODE_FEATURE_NAMES
)

if len(FEATURE_NAMES) != FEATURE_DIM:
    raise RuntimeError(f"FEATURE_NAMES length {len(FEATURE_NAMES)} != FEATURE_DIM {FEATURE_DIM}")

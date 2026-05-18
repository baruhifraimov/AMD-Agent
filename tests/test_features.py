"""Tests for PE feature extraction."""

from unittest.mock import MagicMock, patch

import numpy as np

from src.ml.features import extract_pe_features, features_to_vector
from src.config import FEATURE_NAMES


def test_features_to_vector_shape():
    feats = {k: float(i) for i, k in enumerate(FEATURE_NAMES)}
    vec = features_to_vector(feats)
    assert vec.shape == (len(FEATURE_NAMES),)


@patch("src.ml.features.pefile.PE")
def test_extract_pe_features_mock(mock_pe_cls, minimal_pe_path):
    pe = MagicMock()
    pe.DOS_HEADER.e_cblp = 64
    pe.DOS_HEADER.e_lfanew = 128
    pe.RichHeader = None
    section = MagicMock()
    section.get_data.return_value = b"\x00" * 100
    pe.sections = [section]
    pe.DIRECTORY_ENTRY_IMPORT = []
    pe.OPTIONAL_HEADER.SizeOfImage = 4096
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    pe.OPTIONAL_HEADER.Subsystem = 2
    pe.OPTIONAL_HEADER.DllCharacteristics = 0
    pe.OPTIONAL_HEADER.TimeDateStamp = 12345
    mock_pe_cls.return_value = pe

    feats = extract_pe_features(minimal_pe_path.path)
    assert feats is not None
    assert feats["num_sections"] == 1.0
    assert "avg_section_entropy" in feats

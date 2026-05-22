"""Tests for PESourceStore and PE source classification."""

from src.sources.pe_source_discovery.page_classify import classify_pe_source_page
from src.sources.pe_source_store import PESourceStore


def test_seed_defaults(tmp_paths):
    store = PESourceStore(tmp_paths["db"])
    n = store.seed_defaults()
    assert n >= 3
    assert store.count_active() >= 3


def test_classify_malwarebazaar_page():
    text = "MalwareBazaar community API get_file PE malware samples mb-api.abuse.ch"
    result = classify_pe_source_page("https://bazaar.abuse.ch/api/", text)
    assert result["is_dataset_page"]
    assert result["likely_source_type"] == "malware_only"
    assert result["provider_name"] == "malwarebazaar"

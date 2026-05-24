"""Tests for MalwareBazaar tools, validation, update helpers, and CTI URL extraction."""

from pathlib import Path

import httpx
import pytest

from src.config import FEATURE_NAMES
from src.db.tracker import MalwareTracker
from src.tools import update as update_tool
from src.tools.cti_search import extract_pe_urls
from src.tools.fetch import save_pe_to_sandbox
from src.tools.malwarebazaar_api import download_sample, get_file_type, get_recent_pe, is_pe_sample
from src.tools.validate import file_sha256, is_duplicate, is_pe_mz, is_pe_signature


def test_is_pe_sample_filters():
    assert is_pe_sample({"file_type_mime": "application/x-dosexec"})
    assert is_pe_sample({"magika": "pebin"})
    assert is_pe_sample({"file_type": "exe"})
    assert is_pe_sample({"file_type": "cpl"})
    assert is_pe_sample({"file_type": "mun"})
    assert not is_pe_sample({"file_type": "elf"})


def test_is_pe_mz(minimal_pe_path):
    assert is_pe_mz(minimal_pe_path.path)
    bad = minimal_pe_path.path.parent / "bad.bin"
    bad.write_bytes(b"XX")
    assert not is_pe_mz(bad)


def test_is_pe_signature(minimal_pe_path):
    assert is_pe_signature(minimal_pe_path.path)
    mz_only = minimal_pe_path.path.parent / "mz_only.bin"
    mz_only.write_bytes(b"MZ" + b"\x00" * 128)
    assert not is_pe_signature(mz_only)


def test_file_sha256_matches_path_stem(minimal_pe_path):
    assert file_sha256(minimal_pe_path.path) == minimal_pe_path.sha256


def test_is_duplicate(tmp_paths):
    tracker = MalwareTracker(tmp_paths["db"])
    sha = "a" * 64
    assert not is_duplicate(sha, tracker)
    tracker.insert_pending_hash(sha)
    assert not is_duplicate(sha, tracker)
    tracker.insert_sample(sha, "/tmp/x", "2020-01-01", label=1)
    assert is_duplicate(sha, tracker)


def test_save_pe_to_sandbox(tmp_paths):
    sha = "b" * 64
    path = save_pe_to_sandbox(sha, b"MZ\x00")
    assert path.endswith(".bin")
    assert Path(path).read_bytes()[:2] == b"MZ"


def test_get_file_type_mock(httpx_mock, tmp_paths):
    payload = {
        "query_status": "ok",
        "data": [
            {"sha256_hash": "a" * 64, "file_type": "exe"},
        ],
    }
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        json=payload,
    )
    samples = get_file_type("exe", limit=10)
    assert len(samples) == 1


def test_get_recent_pe_uses_get_recent_by_default(httpx_mock, tmp_paths):
    for prefix in "ab":
        httpx_mock.add_response(
            method="POST",
            url="https://mb-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [
                    {"sha256_hash": prefix * 64, "file_type_mime": "application/x-dosexec"},
                ],
            },
        )
    samples = get_recent_pe(limit=2)
    assert len(samples) == 2
    bodies = [request.content.decode() for request in httpx_mock.get_requests()]
    assert all("query=get_recent" in body for body in bodies)
    assert not any("query=get_file_type" in body for body in bodies)


def test_get_recent_pe_uses_file_type_when_enabled_and_recent_is_dry(httpx_mock, tmp_paths, monkeypatch):
    monkeypatch.setattr("src.config.MB_USE_GET_FILE_TYPE_QUERY", True)
    for _ in ("time", "100"):
        httpx_mock.add_response(
            method="POST",
            url="https://mb-api.abuse.ch/api/v1/",
            json={"query_status": "ok", "data": []},
        )
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        json={
            "query_status": "ok",
            "data": [{"sha256_hash": "b" * 64, "file_type": "dll"}],
        },
    )
    samples = get_recent_pe(limit=1)
    assert len(samples) == 1
    assert samples[0]["sha256_hash"] == "b" * 64
    bodies = [request.content.decode() for request in httpx_mock.get_requests()]
    assert any("query=get_file_type" in body for body in bodies)


def test_get_recent_pe_continues_after_file_type_502(httpx_mock, tmp_paths, monkeypatch):
    monkeypatch.setattr("src.config.MB_USE_GET_FILE_TYPE_QUERY", True)
    for _ in ("time", "100"):
        httpx_mock.add_response(
            method="POST",
            url="https://mb-api.abuse.ch/api/v1/",
            json={"query_status": "ok", "data": []},
        )
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        status_code=502,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        json={
            "query_status": "ok",
            "data": [{"sha256_hash": "b" * 64, "file_type": "dll"}],
        },
    )
    samples = get_recent_pe(limit=1)
    assert len(samples) == 1
    assert samples[0]["sha256_hash"] == "b" * 64


def test_get_recent_pe_filters_non_pe_from_recent(httpx_mock, tmp_paths, monkeypatch):
    monkeypatch.setattr("src.config.MB_USE_GET_FILE_TYPE_QUERY", False)
    monkeypatch.setattr("src.config.MB_SIGINFO_QUERIES", ())
    monkeypatch.setattr("src.config.MB_TAGINFO_QUERIES", ())
    payload = {
        "query_status": "ok",
        "data": [
            {"sha256_hash": "a" * 64, "file_type_mime": "application/x-dosexec"},
            {"sha256_hash": "b" * 64, "file_type": "elf"},
        ],
    }
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        json=payload,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        json={"query_status": "ok", "data": []},
    )
    samples = get_recent_pe(limit=10)
    assert len(samples) == 1


def test_download_sample_zip_response(httpx_mock, infected_zip_bytes, tmp_paths):
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        content=infected_zip_bytes,
        headers={"content-type": "application/zip"},
    )
    raw = download_sample("c" * 64)
    assert raw[:2] == b"MZ"


def test_download_sample_zip_response_with_misleading_json_content_type(
    httpx_mock, infected_zip_bytes, tmp_paths
):
    httpx_mock.add_response(
        method="POST",
        url="https://mb-api.abuse.ch/api/v1/",
        content=infected_zip_bytes,
        headers={"content-type": "application/json"},
    )
    raw = download_sample("d" * 64)
    assert raw[:2] == b"MZ"


def _features(seed: int) -> dict:
    return {name: float(seed) for name in FEATURE_NAMES}


def test_update_insert_and_features(tmp_paths):
    tracker = tmp_paths["tracker"]
    sha = "a" * 64
    update_tool.insert_sample(tracker, sha, "/tmp/a.bin", "2024-01-01", label=1)
    update_tool.update_features(tracker, sha, _features(1))
    assert tracker.get_sample(sha)["features"] is not None


def test_extract_pe_urls_allowlisted():
    text = "Download https://github.com/org/repo/releases/download/v1/sample.exe"
    assert any("github.com" in u for u in extract_pe_urls(text))


def test_extract_pe_urls_skips_non_allowlisted():
    assert extract_pe_urls("Get https://evil.example/malware.exe") == []

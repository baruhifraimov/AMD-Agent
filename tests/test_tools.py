"""Tests for MalwareBazaar tools and validation."""

from pathlib import Path

import httpx
import pytest

from src.tools.fetch import save_pe_to_sandbox
from src.tools.malwarebazaar import get_file_type, get_recent_pe, is_pe_sample, download_sample
from src.tools.validate import file_sha256, is_duplicate, is_pe_mz, is_pe_signature
from src.db.tracker import MalwareTracker


def test_is_pe_sample_filters():
    assert is_pe_sample({"file_type_mime": "application/x-dosexec"})
    assert is_pe_sample({"magika": "pebin"})
    assert is_pe_sample({"file_type": "exe"})
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


def test_get_recent_pe_queries_file_types_before_recent(httpx_mock, tmp_paths):
    for prefix, file_type in zip("abcd", ("exe", "dll", "sys", "scr")):
        httpx_mock.add_response(
            method="POST",
            url="https://mb-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [
                    {"sha256_hash": prefix * 64, "file_type": file_type},
                ],
            },
        )
    samples = get_recent_pe(limit=3)
    assert len(samples) == 3
    bodies = [request.content.decode() for request in httpx_mock.get_requests()]
    assert all(f"file_type={file_type}" in "&".join(bodies) for file_type in ("exe", "dll", "sys", "scr"))
    assert all("query=get_file_type" in body for body in bodies)


def test_get_recent_pe_falls_back_to_recent_when_file_types_are_dry(httpx_mock, tmp_paths):
    for _ in ("exe", "dll", "sys", "scr"):
        httpx_mock.add_response(
            method="POST",
            url="https://mb-api.abuse.ch/api/v1/",
            json={"query_status": "ok", "data": []},
        )
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

"""Tests for BenignNetProvider."""

from pathlib import Path
from unittest.mock import patch

from src.sources.benign_net import BenignNetProvider
from src.sources.base import SampleCandidate


def test_discover_reads_local_exe(tmp_path, monkeypatch):
    repo = tmp_path / "benign-net"
    repo.mkdir()
    exe = repo / "sample.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 126)

    provider = BenignNetProvider()
    with patch.object(provider, "_ensure_repo", return_value=repo):
        candidates = provider.discover(5)

    assert len(candidates) == 1
    assert candidates[0].expected_label == 0
    assert candidates[0].provider == "benign_net"


def test_download_reads_path(tmp_path):
    exe = tmp_path / "foo.exe"
    pe = b"MZ" + b"\x00" * 126
    exe.write_bytes(pe)
    candidate = SampleCandidate(
        external_id=str(exe),
        provider="benign_net",
        expected_label=0,
        download_ref={"path": str(exe)},
    )
    assert BenignNetProvider().download(candidate) == pe

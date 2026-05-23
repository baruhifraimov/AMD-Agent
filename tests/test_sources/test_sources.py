"""PE source provider discover smoke tests."""

from unittest.mock import MagicMock, patch

from src.sources.benign_net import BenignNetProvider
from src.sources.github_releases import GitHubReleasesProvider
from src.sources.malshare import MalShareProvider
from src.sources.sysinternals import SysinternalsProvider

SYSINTERNALS_HTML = """
<html><body>
<a href="Procmon.exe">Procmon</a>
<a href="tools/autoruns.exe">Autoruns</a>
</body></html>
"""


def test_sysinternals_discover(httpx_mock):
    httpx_mock.add_response(url="https://live.sysinternals.com/", text=SYSINTERNALS_HTML)
    httpx_mock.add_response(url="https://live.sysinternals.com/tools/", text=SYSINTERNALS_HTML)
    candidates = SysinternalsProvider().discover(limit=2)
    assert len(candidates) <= 2
    assert all(c.expected_label == 0 for c in candidates)


def test_github_discover_from_release_assets(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.sources.github_releases.GITHUB_BENIGN_REPOS", [("owner", "repo")])
    httpx_mock.add_response(
        url="https://api.github.com/repos/owner/repo/releases/latest",
        json={
            "assets": [
                {"name": "tool.exe", "browser_download_url": "https://example.com/tool.exe"},
            ]
        },
    )
    candidates = GitHubReleasesProvider().discover(limit=5)
    assert len(candidates) == 1


def test_benign_net_discover_reads_local_exe(tmp_path):
    repo = tmp_path / "benign-net"
    repo.mkdir()
    (repo / "sample.exe").write_bytes(b"MZ" + b"\x00" * 126)
    provider = BenignNetProvider()
    with patch.object(provider, "_ensure_repo", return_value=repo):
        candidates = provider.discover(5)
    assert len(candidates) == 1
    assert candidates[0].provider == "benign_net"


def test_malshare_discover_disabled(monkeypatch):
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", False)
    assert MalShareProvider().discover(5) == []


def test_malshare_discover_returns_candidates(monkeypatch):
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", True)
    monkeypatch.setenv("MALSHARE_API_KEY", "k")
    mock_client = MagicMock()
    mock_client.list_pe32_hashes.return_value = [{"hash": "a" * 32}]
    with patch("src.sources.malshare.MalShareClient.from_config", return_value=mock_client):
        candidates = MalShareProvider().discover(3)
    assert len(candidates) == 1
    assert candidates[0].provider == "malshare"

"""Tests for GitHub Releases provider."""

import io
import zipfile

from src.sources.github_releases import GitHubReleasesProvider


def test_discover_from_release_assets(httpx_mock, monkeypatch):
    monkeypatch.setattr(
        "src.sources.github_releases.GITHUB_BENIGN_REPOS",
        [("owner", "repo")],
    )
    httpx_mock.add_response(
        url="https://api.github.com/repos/owner/repo/releases/latest",
        json={
            "assets": [
                {
                    "name": "tool.exe",
                    "browser_download_url": "https://example.com/tool.exe",
                },
                {
                    "name": "bundle.zip",
                    "browser_download_url": "https://example.com/bundle.zip",
                },
                {"name": "notes.md", "browser_download_url": "https://example.com/n.txt"},
            ]
        },
    )
    provider = GitHubReleasesProvider()
    candidates = provider.discover(limit=5)
    assert len(candidates) == 2
    assert candidates[0].metadata["file_name"] == "tool.exe"
    assert candidates[1].metadata["file_name"] == "bundle.zip"


def test_extract_first_pe_from_release_zip_allows_pe_extensions():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", b"not a pe")
        zf.writestr("bin/tool.dll", b"MZdll")

    raw = GitHubReleasesProvider._extract_first_pe_from_zip(buf.getvalue())

    assert raw == b"MZdll"

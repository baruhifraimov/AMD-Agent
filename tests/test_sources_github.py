"""Tests for GitHub Releases provider."""

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
                {"name": "notes.md", "browser_download_url": "https://example.com/n.txt"},
            ]
        },
    )
    provider = GitHubReleasesProvider()
    candidates = provider.discover(limit=5)
    assert len(candidates) == 1
    assert candidates[0].metadata["file_name"] == "tool.exe"

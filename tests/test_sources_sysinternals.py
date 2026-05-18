"""Tests for Sysinternals provider."""

from src.sources.sysinternals import SysinternalsProvider


SYSINTERNALS_HTML = """
<html><body>
<a href="Procmon.exe">Procmon</a>
<a href="tools/autoruns.exe">Autoruns</a>
<a href="readme.txt">Readme</a>
</body></html>
"""


def test_collect_exe_links(httpx_mock):
    httpx_mock.add_response(url="https://live.sysinternals.com/", text=SYSINTERNALS_HTML)
    httpx_mock.add_response(url="https://live.sysinternals.com/tools/", text="<html></html>")

    provider = SysinternalsProvider()
    links = provider._collect_exe_links()
    assert any("Procmon.exe" in u for u in links)
    assert any("autoruns.exe" in u for u in links)


def test_discover_returns_candidates(httpx_mock):
    httpx_mock.add_response(url="https://live.sysinternals.com/", text=SYSINTERNALS_HTML)
    httpx_mock.add_response(url="https://live.sysinternals.com/tools/", text=SYSINTERNALS_HTML)

    provider = SysinternalsProvider()
    candidates = provider.discover(limit=2)
    assert len(candidates) <= 2
    assert all(c.expected_label == 0 for c in candidates)

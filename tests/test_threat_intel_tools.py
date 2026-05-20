"""Tests for threat intel LangChain tool wrappers."""

import json
from unittest.mock import patch

from src.tools import threat_intel_tools as ti_tools


@patch("src.tools.threat_intel_tools._collector")
def test_discover_intel_sources_tool(mock_coll):
    mock_coll.return_value.discover_sources.return_value = {"discovered": 2, "upserted": 2}
    out = json.loads(ti_tools.discover_intel_sources(max_sources=3))
    assert out["discovered"] == 2


@patch("src.tools.threat_intel_tools._collector")
def test_validate_and_queue_tool(mock_coll):
    mock_coll.return_value.validate_and_queue.return_value = {"queued": 1}
    payload = json.dumps({"candidates": [{"sha256": "c" * 64}]})
    out = json.loads(ti_tools.validate_and_queue_candidates(payload))
    assert out["queued"] == 1


@patch("src.tools.threat_intel_tools._collector")
def test_poll_threatingestor_tool(mock_coll):
    mock_coll.return_value.poll_threatingestor_artifacts.return_value = (
        [{"sha256": "d" * 64}],
        {"candidates": 1},
    )
    out = json.loads(ti_tools.poll_threatingestor_artifacts(batch_size=50))
    assert out["count"] == 1


def test_build_intel_tools_returns_four():
    tools = ti_tools.build_intel_tools()
    assert len(tools) == 4

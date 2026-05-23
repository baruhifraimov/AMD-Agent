"""Tests for threat intel LangChain tool wrappers."""

import json
from unittest.mock import patch

from src.tools import threat_intel_tools as ti_tools


@patch("src.tools.threat_intel_tools._collector")
def test_validate_and_queue_tool(mock_coll):
    mock_coll.return_value.validate_and_queue.return_value = {"queued": 1}
    payload = json.dumps({"candidates": [{"sha256": "c" * 64}]})
    out = json.loads(ti_tools.validate_and_queue_candidates(payload))
    assert out["queued"] == 1


def test_build_intel_tools_returns_two():
    tools = ti_tools.build_intel_tools()
    assert len(tools) == 2

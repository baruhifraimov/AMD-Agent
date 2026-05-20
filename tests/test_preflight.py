"""Smoke tests for operational preflight script."""

import sys
from unittest.mock import patch

from scripts.preflight_check import main


def test_preflight_exits_zero_on_empty_db(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["preflight_check.py"])
    assert main() == 0


@patch("scripts.preflight_check.build_collection_context")
@patch("scripts.preflight_check.model_bundle_ready", return_value=False)
@patch("scripts.preflight_check.load_bundle", return_value=None)
def test_preflight_strict_fails_steady_without_bundle(
    mock_load, mock_ready, mock_ctx, monkeypatch
):
    from src.collection.context import CollectionContext

    mock_ctx.return_value = CollectionContext(
        benign_count=100,
        malware_count=100,
        model_ready=False,
        pending_depth=0,
    )
    monkeypatch.setattr(sys, "argv", ["preflight_check.py", "--strict"])
    assert main() == 1

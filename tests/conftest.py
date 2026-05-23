"""Pytest fixtures and collection guards (no pytest.ini — invoke ``pytest tests/``)."""

from __future__ import annotations

import io
import os
import sys
import zipfile
from pathlib import Path

import pyzipper
import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TESTS_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

os.environ.setdefault("MALWAREBAZAAR_AUTH_KEY", "test-key")

# When pytest is run from repo root with no path args, skip non-test trees.
_SKIP_COLLECT_DIRS = frozenset(
    {"src", "scripts", "data", "graphify-out", "report", "docker", "research"}
)


def pytest_ignore_collect(collection_path, config):
    path = Path(collection_path)
    if path.name in _SKIP_COLLECT_DIRS or path.name.startswith("."):
        return True
    if path.is_file() and path.name.startswith("test_") and _TESTS_ROOT not in path.parents:
        return True
    return False


from src.config import DB_PATH, MODEL_PATH, ADWIN_PATH, SANDBOX_DIR


def minimal_pe_bytes() -> bytes:
    content = bytearray(b"MZ" + b"\x00" * 126)
    content[0x3C:0x40] = (0x80).to_bytes(4, "little")
    content.extend(b"PE\x00\x00")
    content.extend(b"\x00" * 64)
    return bytes(content)


@pytest.fixture
def tmp_paths(tmp_path, monkeypatch):
    """Isolate DB, model, sandbox paths per test."""
    db = tmp_path / "test.db"
    model = tmp_path / "model.pkl"
    adwin = tmp_path / "adwin.joblib"
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    benign = tmp_path / "benign"
    benign.mkdir()

    monkeypatch.setattr("src.config.DB_PATH", db)
    monkeypatch.setattr("src.config.MODEL_PATH", model)
    monkeypatch.setattr("src.config.ADWIN_PATH", adwin)
    monkeypatch.setattr("src.config.SANDBOX_DIR", sandbox)
    monkeypatch.setattr("src.tools.fetch.SANDBOX_DIR", sandbox)
    monkeypatch.setattr("src.config.BENIGN_DIR", benign)
    monkeypatch.setattr("src.config.EVAL_LOG_PATH", tmp_path / "eval.jsonl")
    monkeypatch.setattr("src.config.EVAL_STATE_PATH", tmp_path / "eval_state.json")
    monkeypatch.setattr("src.config.DRIFT_LOG_PATH", tmp_path / "drift.jsonl")
    monkeypatch.setattr("src.config.MODEL_UPDATE_LOG_PATH", tmp_path / "model_update.jsonl")
    monkeypatch.setattr("src.config.FIGURES_DIR", tmp_path / "figures")
    monkeypatch.setattr(
        "src.nodes.evaluation_node.EVAL_STATE_PATH",
        tmp_path / "eval_state.json",
        raising=False,
    )
    monkeypatch.setenv("MALWAREBAZAAR_AUTH_KEY", "test-key")

    from src.db.tracker import MalwareTracker

    tracker = MalwareTracker(db)

    def _get_tracker(db_path=None):
        return tracker if db_path is None else MalwareTracker(db_path)

    monkeypatch.setattr("src.db.tracker.get_tracker", _get_tracker)
    monkeypatch.setattr("src.tools.clients.malwarebazaar_api_client.get_tracker", _get_tracker)
    return {"db": db, "model": model, "adwin": adwin, "sandbox": sandbox, "benign": benign, "tracker": tracker}


@pytest.fixture
def infected_zip_bytes():
    """Create AES ZIP with password 'infected' containing fake PE bytes."""
    pe = minimal_pe_bytes()
    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"infected")
        zf.writestr("sample.bin", pe)
    return buf.getvalue()


@pytest.fixture
def minimal_pe_path(tmp_paths):
    import hashlib
    from types import SimpleNamespace

    content = minimal_pe_bytes()
    sha = hashlib.sha256(content).hexdigest()
    path = tmp_paths["sandbox"] / f"{sha}.bin"
    path.write_bytes(content)
    return SimpleNamespace(path=path, sha256=sha)

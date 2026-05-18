"""Pytest fixtures."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pyzipper
import pytest

from src.config import DB_PATH, MODEL_PATH, ADWIN_PATH, SANDBOX_DIR


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
    monkeypatch.setattr("src.config.BENIGN_DIR", benign)
    monkeypatch.setattr("src.config.EVAL_LOG_PATH", tmp_path / "eval.jsonl")
    monkeypatch.setattr("src.config.FIGURES_DIR", tmp_path / "figures")
    monkeypatch.setenv("MALWAREBAZAAR_AUTH_KEY", "test-key")

    from src.db.tracker import MalwareTracker

    tracker = MalwareTracker(db)
    monkeypatch.setattr(
        "src.db.tracker.get_tracker",
        lambda db_path=None: tracker if db_path is None else MalwareTracker(db_path),
    )
    return {"db": db, "model": model, "adwin": adwin, "sandbox": sandbox, "benign": benign, "tracker": tracker}


@pytest.fixture
def infected_zip_bytes():
    """Create AES ZIP with password 'infected' containing fake PE bytes."""
    pe = b"MZ" + b"\x00" * 64
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

    content = b"MZ" + b"\x00" * 128
    sha = hashlib.sha256(content).hexdigest()
    path = tmp_paths["sandbox"] / f"{sha}.bin"
    path.write_bytes(content)
    return SimpleNamespace(path=path, sha256=sha)

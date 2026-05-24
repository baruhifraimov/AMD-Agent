"""Environment secrets (Pydantic) and accessor helpers.

Secrets live in `.env` (see `.env.example`). Tuning flags live in `core.py` / `providers.py`.
"""

from __future__ import annotations

import os

from pydantic import BaseModel

_secrets_instance: AppSecrets | None = None


# --- Pydantic model (loaded once from environment) ---


class AppSecrets(BaseModel):
    malwarebazaar_auth_key: str = ""
    github_token: str = ""
    malshare_api_key: str = ""
    otx_api_key: str = ""
    ollama_base_url: str = ""
    ollama_model: str = ""

    @classmethod
    def from_env(cls) -> AppSecrets:
        return cls(
            malwarebazaar_auth_key=os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip(),
            github_token=os.getenv("GITHUB_TOKEN", "").strip(),
            malshare_api_key=os.getenv("MALSHARE_API_KEY", "").strip(),
            otx_api_key=os.getenv("OTX_API_KEY", "").strip(),
            ollama_base_url=os.getenv("AMD_OLLAMA_BASE_URL").strip(),
            ollama_model=os.getenv("AMD_OLLAMA_MODEL").strip(),
        )


def get_secrets() -> AppSecrets:
    global _secrets_instance
    if _secrets_instance is None:
        _secrets_instance = AppSecrets.from_env()
    return _secrets_instance


# --- Module-level mirrors (legacy: from src.config import OTX_API_KEY) ---


def _refresh_env_constants() -> None:
    s = get_secrets()
    globals()["OTX_API_KEY"] = s.otx_api_key
    globals()["OLLAMA_BASE_URL"] = s.ollama_base_url
    globals()["OLLAMA_MODEL"] = s.ollama_model


OTX_API_KEY = ""
OLLAMA_BASE_URL = ""
OLLAMA_MODEL = ""
_refresh_env_constants()


# --- Required-key accessors (fail fast when missing) ---


def get_auth_key() -> str:
    key = get_secrets().malwarebazaar_auth_key
    if not key:
        raise ValueError("Missing MALWAREBAZAAR_AUTH_KEY environment variable")
    return key


def get_github_token() -> str:
    return get_secrets().github_token


def get_malshare_api_key() -> str:
    key = get_secrets().malshare_api_key
    if not key:
        raise ValueError("Missing MALSHARE_API_KEY environment variable")
    return key


# --- Feature-flag helpers (read live src.config for monkeypatch-safe tests) ---


def _config():
    import src.config as config

    return config


def allow_local_benign() -> bool:
    return _config().ALLOW_LOCAL_BENIGN


def malshare_enabled() -> bool:
    return _config().MALSHARE_ENABLED


def otx_enabled() -> bool:
    cfg = _config()
    return cfg.OTX_ENABLED and bool(cfg.OTX_API_KEY)


def mb_fallback_malshare() -> bool:
    return _config().MB_FALLBACK_MALSHARE


def pe_source_discovery_enabled() -> bool:
    return _config().PE_SOURCE_DISCOVERY_ENABLED


def ollama_source_selection_enabled() -> bool:
    return _config().OLLAMA_SOURCE_SELECTION_ENABLED


def ollama_drift_context_report_enabled() -> bool:
    return _config().OLLAMA_DRIFT_CONTEXT_REPORT_ENABLED

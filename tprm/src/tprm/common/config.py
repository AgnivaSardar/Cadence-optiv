"""Application configuration using Pydantic BaseSettings v2.

Secrets (TPRM_VAULT_KEY, GATE_SIGNING_KEY) are loaded from environment
variables only — never from YAML config files.

YAML config files (policy.yaml, risk_taxonomy.yaml, etc.) are loaded here
once and cached; stages access them via ``get_settings()``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default config directory relative to the repo root
# src/tprm/common/config.py → parents[3] = tprm/ root
_DEFAULT_CONFIG_DIR = Path(__file__).parents[3] / "config"


class Settings(BaseSettings):
    """Application settings.

    Values with defaults can be overridden via environment variables
    (case-insensitive, prefixed with ``TPRM_``).
    """

    model_config = SettingsConfigDict(
        env_prefix="TPRM_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",   # silently ignore env vars that aren't declared fields
    )

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://tprm:tprm@localhost:5432/tprm",
        description="Async SQLAlchemy database URL",
    )

    # ── Ollama / LLM ─────────────────────────────────────────────────────────
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Ollama base URL",
    )
    llm_model: str = Field(
        default="llama3.2:3b",
        description="Ollama model name",
    )
    llm_max_retries: int = Field(default=2, description="Max JSON-repair retries")

    # ── Security flags ────────────────────────────────────────────────────────
    allow_detokenize: bool = Field(
        default=False,
        description="Enable vault detokenization API (disabled by default)",
    )

    # ── OneTrust adapter ──────────────────────────────────────────────────────
    onetrust_adapter: str = Field(
        default="mock",
        description="'mock' or 'http'",
    )
    onetrust_base_url: str = Field(
        default="",
        description="OneTrust API base URL (required for http adapter)",
    )
    onetrust_client_id: str = Field(default="", description="OAuth2 client ID")
    onetrust_client_secret: str = Field(default="", description="OAuth2 client secret")

    # ── API ───────────────────────────────────────────────────────────────────
    api_key: str = Field(
        default="dev-insecure-key",
        description="API key for authentication (override in production)",
    )

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=False)

    # ── Config file paths ─────────────────────────────────────────────────────
    config_dir: Path = Field(default=_DEFAULT_CONFIG_DIR)

    @field_validator("onetrust_adapter")
    @classmethod
    def validate_adapter(cls, v: str) -> str:
        if v not in {"mock", "http"}:
            raise ValueError("onetrust_adapter must be 'mock' or 'http'")
        return v

    # ── YAML loaders (cached on first access) ─────────────────────────────────

    def _load_yaml(self, filename: str) -> dict[str, Any]:
        path = self.config_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with path.open() as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"Config file {filename} must contain a YAML mapping at top level")
        return data

    @property
    def policy(self) -> dict[str, Any]:
        """Parsed policy.yaml contents."""
        return self._load_yaml("policy.yaml")

    @property
    def risk_taxonomy(self) -> dict[str, Any]:
        """Parsed risk_taxonomy.yaml contents."""
        return self._load_yaml("risk_taxonomy.yaml")

    @property
    def controls(self) -> dict[str, Any]:
        """Parsed controls.yaml contents."""
        return self._load_yaml("controls.yaml")

    @property
    def workflow(self) -> dict[str, Any]:
        """Parsed workflow.yaml contents."""
        return self._load_yaml("workflow.yaml")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()


def override_settings(**kwargs: Any) -> Settings:
    """Create a Settings instance with overridden values (for testing)."""
    get_settings.cache_clear()
    instance = Settings(**kwargs)
    # Monkey-patch the cache so get_settings() returns this instance
    get_settings.cache_clear()

    @lru_cache(maxsize=1)  # type: ignore[misc]
    def _patched() -> Settings:
        return instance

    import tprm.common.config as _mod

    _mod.get_settings = _patched  # type: ignore[assignment]
    return instance

"""Simulated customer KMS (separate trust domain). Key APIs arrive in M3."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinel_vault.config import LogLevel, require_loopback
from sentinel_vault.security.http import build_app


class KmsSettings(BaseSettings):
    """Own env prefix and own data dir: the KMS never reads Sentinel's files or vice versa."""

    model_config = SettingsConfigDict(env_prefix="KMS_", extra="forbid", frozen=True)

    data_dir: Path = Path(".run/kms")
    host: str = "127.0.0.1"
    port: int = Field(default=8100, ge=1024, le=65535)
    log_level: LogLevel = "INFO"

    @field_validator("host")
    @classmethod
    def _loopback_only(cls, v: str) -> str:
        return require_loopback(v)


def create_app(settings: KmsSettings | None = None, configure_logs: bool = True) -> FastAPI:
    settings = settings or KmsSettings()
    app = build_app("customer-kms", "Customer KMS (simulated)", settings.log_level,
                    configure_logs)
    app.state.settings = settings
    return app

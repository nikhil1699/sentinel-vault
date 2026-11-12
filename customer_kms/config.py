"""KMS settings. Own env prefix and data dir: the KMS never reads Sentinel's files."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinel_vault.config import LogLevel, require_loopback


class KmsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KMS_", extra="forbid", frozen=True)

    data_dir: Path = Path(".run/kms")
    host: str = "127.0.0.1"
    port: int = Field(default=8100, ge=1024, le=65535)
    log_level: LogLevel = "INFO"
    max_body_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)

    @field_validator("host")
    @classmethod
    def _loopback_only(cls, v: str) -> str:
        return require_loopback(v)

"""Service settings. Loaded from environment variables prefixed ``SV_``.

Every value has a safe default so ``./run.sh`` works with no configuration.
Values that would weaken security (non-loopback binds, unbounded caches) are rejected.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]


def require_loopback(host: str) -> str:
    """Reject any bind address that is not loopback. Shared by every service."""
    if host == "localhost":
        return host
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("host must be a loopback IP address or 'localhost'") from exc
    if not addr.is_loopback:
        raise ValueError("host must be loopback; this POC never binds a public interface")
    return host


class Settings(BaseSettings):
    """Settings for the Sentinel API and rotation worker (our trust domain)."""

    model_config = SettingsConfigDict(env_prefix="SV_", extra="forbid", frozen=True)

    data_dir: Path = Path(".run/data")
    secrets_dir: Path = Path(".secrets")
    log_level: LogLevel = "INFO"

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1024, le=65535)
    kms_url: str = "http://127.0.0.1:8100"
    llm_url: str = "http://127.0.0.1:8200"

    # DEK cache (PLAN §6). TTL 0 = no caching (strict customers).
    dek_cache_ttl_seconds: int = Field(default=300, ge=0, le=3600)
    dek_cache_max_uses: int = Field(default=10_000, ge=1, le=1_000_000)

    # Workspace DEK roll (PLAN §4). Upper bound keeps random-nonce GCM far below 2^32 msgs.
    dek_max_age_seconds: int = Field(default=86_400, ge=60, le=7 * 86_400)
    dek_max_uses: int = Field(default=1_000_000, ge=1, le=2**30)

    # Sessions (PLAN §17).
    session_idle_seconds: int = Field(default=1_800, ge=60, le=86_400)
    session_absolute_seconds: int = Field(default=43_200, ge=300, le=7 * 86_400)
    max_sessions_per_user: int = Field(default=10, ge=1, le=100)

    # Passwords: Argon2id. Defaults follow RFC 9106 second recommended option.
    # Tests lower cost; floors stop a config typo from disabling hashing cost entirely.
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_kib: int = Field(default=65_536, ge=8, le=1_048_576)
    argon2_parallelism: int = Field(default=4, ge=1, le=8)
    password_min_length: int = Field(default=12, ge=8, le=128)

    # Login throttling, per attempted user and per client IP.
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_lockout_base_seconds: float = Field(default=1.0, ge=0.0, le=60.0)
    login_lockout_max_seconds: float = Field(default=900.0, ge=1.0, le=86_400.0)

    @property
    def auth_db_path(self) -> Path:
        return self.data_dir / "auth.db"

    @field_validator("api_host")
    @classmethod
    def _loopback_only(cls, v: str) -> str:
        return require_loopback(v)

    @model_validator(mode="after")
    def _session_bounds(self) -> Self:
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise ValueError("session_idle_seconds must not exceed session_absolute_seconds")
        return self

    @property
    def service_private_key_path(self) -> Path:
        return self.secrets_dir / "service_ed25519.pem"

    @property
    def service_public_key_path(self) -> Path:
        return self.secrets_dir / "service_ed25519.pub.pem"

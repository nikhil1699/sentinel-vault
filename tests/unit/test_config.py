from __future__ import annotations

import pytest
from pydantic import ValidationError

from customer_kms.app import KmsSettings
from sentinel_vault.config import Settings


def test_defaults_are_safe() -> None:
    s = Settings()
    assert s.api_host == "127.0.0.1"
    assert s.dek_cache_ttl_seconds == 300
    assert s.max_sessions_per_user == 10


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SV_API_PORT", "9001")
    monkeypatch.setenv("SV_DEK_CACHE_TTL_SECONDS", "0")
    s = Settings()
    assert s.api_port == 9001
    assert s.dek_cache_ttl_seconds == 0


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "10.0.0.5", "::", "example.com", "8.8.8.8"]  # noqa: S104
)
def test_rejects_non_loopback_bind(host: str) -> None:
    with pytest.raises(ValidationError):
        Settings(api_host=host)
    with pytest.raises(ValidationError):
        KmsSettings(host=host)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.0.0.2"])
def test_accepts_loopback(host: str) -> None:
    assert Settings(api_host=host).api_host == host


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_port", 80),
        ("api_port", 70000),
        ("dek_cache_ttl_seconds", -1),
        ("dek_cache_ttl_seconds", 86_400),
        ("dek_cache_max_uses", 0),
        ("dek_max_uses", 2**31),
        ("max_sessions_per_user", 0),
        ("log_level", "TRACE"),
    ],
)
def test_rejects_bad_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_idle_must_not_exceed_absolute() -> None:
    with pytest.raises(ValidationError):
        Settings(session_idle_seconds=7200, session_absolute_seconds=3600)


def test_unknown_setting_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(**{"debug_dump_keys": True})  # type: ignore[arg-type]


def test_frozen() -> None:
    s = Settings()
    with pytest.raises(ValidationError):
        s.api_port = 9999  # type: ignore[misc]

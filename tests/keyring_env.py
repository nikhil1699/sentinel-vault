"""Keyring wired to the simulated customer KMS for tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from sentinel_vault.config import Settings
from sentinel_vault.crypto.dek_cache import DekCache
from sentinel_vault.domain.ids import TenantId
from sentinel_vault.kms_client.provider import SignedKmsProvider
from sentinel_vault.persistence.keyring_store import KeyringStore
from sentinel_vault.persistence.sqlite import create_sqlite_engine
from sentinel_vault.service.keyring import Keyring
from tests.conftest import FakeClock
from tests.kms_env import SERVICE, KmsEnv, kms_env


@dataclass
class KeyringEnv:
    kms: KmsEnv
    provider: SignedKmsProvider
    keyring: Keyring
    store: KeyringStore
    cmks: dict[str, str]


@asynccontextmanager
async def keyring_env(tmp_path: Path, settings: Settings, clock: FakeClock,
                      accounts: tuple[str, ...] = ("acme", "beta"),
                      onboard: bool = True) -> AsyncIterator[KeyringEnv]:
    async with kms_env(tmp_path, clock, accounts) as env:
        provider = SignedKmsProvider(env.http, SERVICE, env.service_key, max_retries=1,
                                     clock=clock)
        engine = create_sqlite_engine(settings.keyring_db_path)
        store = KeyringStore(engine)
        await store.create_schema()
        cache = DekCache(settings.dek_cache_ttl_seconds, settings.dek_cache_max_uses,
                         clock=clock)
        kr = Keyring(store, provider, cache, settings, clock)
        cmks: dict[str, str] = {}
        if onboard:
            for a in accounts:
                cmks[a] = await env.onboard(a)
                await kr.onboard(TenantId(a), a, cmks[a])
        try:
            yield KeyringEnv(env, provider, kr, store, cmks)
        finally:
            await engine.dispose()

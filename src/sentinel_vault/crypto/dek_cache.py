"""Plaintext DEK cache (PLAN §6), modeled on the AWS Encryption SDK caching CMM.

- Key ``(tenant_id, dek_id)``. Evicted at TTL or max uses, whichever first.
- Eviction zeroes the buffer.
- TTL 0 disables caching: every use unwraps via KMS and the key is wiped right after.
- Concurrent misses for the same key share one KMS call (single flight).
- Keys are used inside a **synchronous** callback. No ``await`` can happen while a
  caller holds the key, so another task can't evict and zero it mid-use.

Revocation latency = TTL. ``evict_tenant`` / ``flush`` cut it to zero on demand.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TypeVar

from sentinel_vault.crypto.wipe import wipe
from sentinel_vault.domain.ids import DekId, TenantId

T = TypeVar("T")
Loader = Callable[[], Awaitable[bytearray]]


@dataclass(slots=True)
class _Entry:
    key: bytearray
    expires_at: float
    uses: int = 0


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    loads: int = 0
    by_tenant_loads: dict[str, int] = field(default_factory=dict)


class DekCache:
    def __init__(self, ttl_seconds: float, max_uses: int, max_entries: int = 10_000,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = ttl_seconds
        self._max_uses = max_uses
        self._max_entries = max_entries
        self._clock = clock
        self._entries: dict[tuple[str, str], _Entry] = {}
        self._inflight: dict[tuple[str, str], asyncio.Future[bytearray]] = {}
        self.stats = CacheStats()

    def __len__(self) -> int:
        return len(self._entries)

    def _evict(self, k: tuple[str, str]) -> None:
        e = self._entries.pop(k, None)
        if e is not None:
            wipe(e.key)
            self.stats.evictions += 1

    def _fresh(self, k: tuple[str, str]) -> _Entry | None:
        e = self._entries.get(k)
        if e is None:
            return None
        if self._clock() >= e.expires_at or e.uses >= self._max_uses:
            self._evict(k)
            return None
        return e

    async def _load(self, k: tuple[str, str], loader: Loader) -> bytearray:
        fut = self._inflight.get(k)
        if fut is not None:
            return await asyncio.shield(fut)
        fut = asyncio.get_running_loop().create_future()
        self._inflight[k] = fut
        try:
            key = await loader()
            self.stats.loads += 1
            self.stats.by_tenant_loads[k[0]] = self.stats.by_tenant_loads.get(k[0], 0) + 1
            fut.set_result(key)
            return key
        except BaseException as exc:
            fut.set_exception(exc)
            fut.exception()  # mark retrieved; waiters get it via await
            raise
        finally:
            del self._inflight[k]

    async def use(self, tenant_id: TenantId, dek_id: DekId, loader: Loader,
                  fn: Callable[[bytearray], T], uses: int = 1) -> T:
        """Run ``fn(key)`` synchronously with the plaintext DEK for ``(tenant, dek)``."""
        k = (str(tenant_id), str(dek_id))
        if self._ttl <= 0:
            # No caching and no single flight: a shared buffer would be wiped by the
            # first caller before the second one used it.
            self.stats.misses += 1
            key = await loader()
            self.stats.loads += 1
            try:
                return fn(key)
            finally:
                wipe(key)
        e = self._fresh(k)
        if e is not None:
            self.stats.hits += 1
            e.uses += uses
            return fn(e.key)
        self.stats.misses += 1
        key = await self._load(k, loader)
        e = self._fresh(k)  # another waiter may have cached it already
        if e is not None and e.key is not key:
            wipe(key)  # duplicate copy from a racing load; keep the cached one
            e.uses += uses
            return fn(e.key)
        if e is None:
            if len(self._entries) >= self._max_entries:
                self._evict(next(iter(self._entries)))
            e = _Entry(key, self._clock() + self._ttl)
            self._entries[k] = e
        e.uses += uses
        return fn(e.key)

    def put(self, tenant_id: TenantId, dek_id: DekId, key: bytearray) -> None:
        """Cache a freshly generated DEK (from GenerateDataKey). Takes ownership."""
        if self._ttl <= 0:
            wipe(key)
            return
        k = (str(tenant_id), str(dek_id))
        self._evict(k)
        if len(self._entries) >= self._max_entries:
            self._evict(next(iter(self._entries)))
        self._entries[k] = _Entry(key, self._clock() + self._ttl)

    def evict_dek(self, tenant_id: TenantId, dek_id: DekId) -> None:
        self._evict((str(tenant_id), str(dek_id)))

    def evict_tenant(self, tenant_id: TenantId) -> int:
        ks = [k for k in self._entries if k[0] == tenant_id]
        for k in ks:
            self._evict(k)
        return len(ks)

    def flush(self) -> None:
        for k in list(self._entries):
            self._evict(k)

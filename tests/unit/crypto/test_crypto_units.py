"""Unit tests: envelope AEAD, key wiping, DEK cache."""

from __future__ import annotations

import asyncio

import pytest

from sentinel_vault.crypto.dek_cache import DekCache
from sentinel_vault.crypto.envelope import (
    DecryptionError,
    Sealed,
    canonical_aad,
    open_sealed,
    seal,
)
from sentinel_vault.crypto.wipe import is_wiped, wipe
from sentinel_vault.domain.ids import DekId, TenantId
from tests.conftest import FakeClock

KEY = bytes(range(32))
AAD = canonical_aad({"tenant_id": "acme", "doc_id": "doc_x", "n": 1})

# --- envelope -------------------------------------------------------------------------------


def test_roundtrip_and_nonce_unique() -> None:
    s1, s2 = seal(KEY, b"phi", AAD), seal(KEY, b"phi", AAD)
    assert open_sealed(KEY, s1, AAD) == b"phi"
    assert s1.nonce != s2.nonce and s1.ciphertext != s2.ciphertext
    assert b"phi" not in s1.ciphertext


def test_aad_is_canonical() -> None:
    assert canonical_aad({"b": 1, "a": "x"}) == canonical_aad({"a": "x", "b": 1})
    with pytest.raises(TypeError):
        canonical_aad({"a": 1.5})  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        canonical_aad({"a": True})


@pytest.mark.parametrize("mutate", ["ct", "nonce", "tag", "aad", "key", "short_nonce"])
def test_tamper_detected(mutate: str) -> None:
    s = seal(KEY, b"patient record", AAD)
    key, aad, nonce, ct = bytearray(KEY), AAD, s.nonce, bytearray(s.ciphertext)
    if mutate == "ct":
        ct[0] ^= 1
    elif mutate == "tag":
        ct[-1] ^= 1
    elif mutate == "nonce":
        nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
    elif mutate == "aad":
        aad = canonical_aad({"tenant_id": "beta", "doc_id": "doc_x", "n": 1})
    elif mutate == "key":
        key[0] ^= 1
    else:
        nonce = nonce[:8]
    with pytest.raises(DecryptionError):
        open_sealed(key, Sealed(nonce, bytes(ct)), aad)


def test_key_length_enforced() -> None:
    with pytest.raises(ValueError):
        seal(b"short", b"x", AAD)


def test_wipe() -> None:
    b = bytearray(b"secret-key-material")
    wipe(b)
    assert is_wiped(b) and len(b) == 19
    wipe(bytearray())


# --- DEK cache --------------------------------------------------------------------------------

T, D1, D2 = TenantId("acme"), DekId.new(), DekId.new()


class Loader:
    def __init__(self, delay: float = 0.0) -> None:
        self.calls = 0
        self.issued: list[bytearray] = []
        self.delay = delay

    async def __call__(self) -> bytearray:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        k = bytearray(KEY)
        self.issued.append(k)
        return k


async def test_cache_hit_avoids_reload(clock: FakeClock) -> None:
    c, ld = DekCache(300, 1000, clock=clock), Loader()
    for _ in range(50):
        assert await c.use(T, D1, ld, bytes) == KEY
    assert ld.calls == 1 and c.stats.hits == 49


async def test_ttl_expiry_wipes(clock: FakeClock) -> None:
    c, ld = DekCache(300, 1000, clock=clock), Loader()
    await c.use(T, D1, ld, len)
    clock.advance(301)
    await c.use(T, D1, ld, len)
    assert ld.calls == 2
    assert is_wiped(ld.issued[0])


async def test_max_uses_eviction(clock: FakeClock) -> None:
    c, ld = DekCache(300, 10, clock=clock), Loader()
    await c.use(T, D1, ld, len, uses=10)
    await c.use(T, D1, ld, len)
    assert ld.calls == 2 and is_wiped(ld.issued[0])


async def test_ttl_zero_never_caches_and_wipes(clock: FakeClock) -> None:
    c, ld = DekCache(0, 1000, clock=clock), Loader()
    for _ in range(3):
        assert await c.use(T, D1, ld, bytes) == KEY
    assert ld.calls == 3 and len(c) == 0
    assert all(is_wiped(k) for k in ld.issued)
    c.put(T, D2, bytearray(KEY))
    assert len(c) == 0


async def test_ttl_zero_concurrent_callers_each_get_a_valid_key(clock: FakeClock) -> None:
    """Regression: with caching off, a shared buffer would reach the 2nd caller zeroed."""
    c, ld = DekCache(0, 1000, clock=clock), Loader(delay=0.01)
    results = await asyncio.gather(*(c.use(T, D1, ld, bytes) for _ in range(5)))
    assert all(r == KEY for r in results)


async def test_single_flight(clock: FakeClock) -> None:
    c, ld = DekCache(300, 1000, clock=clock), Loader(delay=0.01)
    results = await asyncio.gather(*(c.use(T, D1, ld, bytes) for _ in range(20)))
    assert ld.calls == 1 and all(r == KEY for r in results)


async def test_loader_failure_propagates_to_all_waiters(clock: FakeClock) -> None:
    c = DekCache(300, 1000, clock=clock)

    async def boom() -> bytearray:
        await asyncio.sleep(0.01)
        raise RuntimeError("kms down")

    res = await asyncio.gather(*(c.use(T, D1, boom, len) for _ in range(3)),
                               return_exceptions=True)
    assert all(isinstance(r, RuntimeError) for r in res)
    assert len(c) == 0


async def test_evict_tenant_and_flush(clock: FakeClock) -> None:
    c, ld = DekCache(300, 1000, clock=clock), Loader()
    await c.use(T, D1, ld, len)
    await c.use(TenantId("beta"), D2, ld, len)
    assert c.evict_tenant(T) == 1
    assert is_wiped(ld.issued[0]) and not is_wiped(ld.issued[1])
    c.flush()
    assert is_wiped(ld.issued[1]) and len(c) == 0


async def test_put_then_hit_and_capacity(clock: FakeClock) -> None:
    c, ld = DekCache(300, 1000, max_entries=2, clock=clock), Loader()
    first = bytearray(KEY)
    c.put(T, D1, first)
    assert await c.use(T, D1, ld, bytes) == KEY and ld.calls == 0
    c.put(T, D2, bytearray(KEY))
    c.put(T, DekId.new(), bytearray(KEY))  # evicts oldest
    assert len(c) == 2 and is_wiped(first)
    c.evict_dek(T, D2)
    assert len(c) == 1


async def test_tenants_dont_share_entries(clock: FakeClock) -> None:
    c, ld = DekCache(300, 1000, clock=clock), Loader()
    await c.use(TenantId("acme"), D1, ld, len)
    await c.use(TenantId("beta"), D1, ld, len)  # same dek id string, different tenant
    assert ld.calls == 2

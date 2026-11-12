"""Keyring + customer KMS: BYOK envelope encryption end to end (M4)."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from sentinel_vault.config import Settings
from sentinel_vault.domain.ids import DekId, TenantId, WorkspaceId
from sentinel_vault.kms_client.provider import (
    DataIntegrityError,
    TenantKeyUnavailableError,
)
from sentinel_vault.persistence.keyring_store import DekState, Purpose
from sentinel_vault.security.errors import DependencyUnavailableError, NotFoundError
from sentinel_vault.service.keyring import TenantNotOnboardedError
from tests.conftest import FakeClock
from tests.keyring_env import keyring_env

ACME, BETA = TenantId("acme"), TenantId("beta")
WS = WorkspaceId("default")


def items(n: int, doc: str = "doc_a") -> list[tuple[dict[str, str | int], bytes]]:
    return [({"doc_id": doc, "chunk": i}, f"chunk {i} John Smith".encode()) for i in range(n)]


async def test_onboarding_probe(tmp_path: Path, settings: Settings, clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock, onboard=False) as e:
        # customer created a key but didn't grant us -> onboarding refused
        cmk = await e.kms.admin("acme").create_key()
        with pytest.raises(TenantKeyUnavailableError):
            await e.keyring.onboard(ACME, "acme", cmk)
        assert not await e.keyring.is_onboarded(ACME)
        # customer's policy is for tenant beta -> refused for acme
        from tests.kms_env import tenant_policy
        await e.kms.admin("acme").put_key_policy(cmk, tenant_policy("beta"))
        with pytest.raises(TenantKeyUnavailableError):
            await e.keyring.onboard(ACME, "acme", cmk)
        await e.kms.admin("acme").put_key_policy(cmk, tenant_policy("acme"))
        await e.keyring.onboard(ACME, "acme", cmk)
        assert await e.keyring.is_onboarded(ACME)


async def test_not_onboarded(tmp_path: Path, settings: Settings, clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock, onboard=False) as e:
        with pytest.raises(TenantNotOnboardedError):
            await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))


async def test_roundtrip_one_kms_call_for_many_chunks(tmp_path: Path, settings: Settings,
                                                      clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        before = e.provider.calls
        enc = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(50))
        assert e.provider.calls - before == 1  # one GenerateDataKey for 50 chunks
        assert len({x.dek_id for x in enc}) == 1
        e.keyring.flush_tenant(ACME)
        before = e.provider.calls
        out = await e.keyring.decrypt(ACME, enc[0].dek_id, [
            (f, x.nonce, x.ciphertext) for (f, _), x in zip(items(50), enc, strict=True)])
        assert out == [pt for _, pt in items(50)]
        assert e.provider.calls - before == 1  # one Decrypt for 50 chunks
        before = e.provider.calls
        await e.keyring.decrypt(ACME, enc[0].dek_id, [(items(1)[0][0], enc[0].nonce,
                                                       enc[0].ciphertext)])
        assert e.provider.calls == before  # cache hit: zero calls


async def test_aad_binding(tmp_path: Path, settings: Settings, clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        for wrong in ({"doc_id": "doc_b", "chunk": 0}, {"doc_id": "doc_a", "chunk": 1}, {}):
            with pytest.raises(DataIntegrityError):
                await e.keyring.decrypt(ACME, x.dek_id, [(wrong, x.nonce, x.ciphertext)])
        with pytest.raises(ValueError):
            await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, [({"tenant_id": "beta"}, b"x")])


async def test_cross_tenant_dek_lookup(tmp_path: Path, settings: Settings,
                                       clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        with pytest.raises(NotFoundError):
            await e.keyring.decrypt(BETA, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])
        with pytest.raises(NotFoundError):
            await e.keyring.decrypt(ACME, DekId.new(), [({}, b"", b"")])


async def test_wrapped_dek_swapped_between_tenants_in_db(tmp_path: Path, settings: Settings,
                                                         clock: FakeClock) -> None:
    """Insider copies acme's wrapped DEK into beta's DEK row. Beta's CMK/policy refuses."""
    async with keyring_env(tmp_path, settings, clock) as e:
        [a] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        [b] = await e.keyring.encrypt(BETA, WS, Purpose.VECTOR, items(1))
        with sqlite3.connect(settings.keyring_db_path) as db:
            wrapped = db.execute("select wrapped from deks where dek_id=?",
                                 (a.dek_id,)).fetchone()[0]
            db.execute("update deks set wrapped=? where dek_id=?", (wrapped, b.dek_id))
        e.keyring.cache.flush()
        with pytest.raises(TenantKeyUnavailableError):
            await e.keyring.decrypt(BETA, b.dek_id, [(items(1)[0][0], b.nonce, b.ciphertext)])


async def test_tampered_wrapped_dek(tmp_path: Path, settings: Settings,
                                    clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        with sqlite3.connect(settings.keyring_db_path) as db:
            w = bytearray(db.execute("select wrapped from deks where dek_id=?",
                                     (x.dek_id,)).fetchone()[0])
            w[-1] ^= 1
            db.execute("update deks set wrapped=? where dek_id=?", (bytes(w), x.dek_id))
        e.keyring.cache.flush()
        with pytest.raises(DataIntegrityError):
            await e.keyring.decrypt(ACME, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])


async def test_dek_rolls_at_max_uses(tmp_path: Path, settings: Settings,
                                     clock: FakeClock) -> None:
    s = settings.model_copy(update={"dek_max_uses": 10})
    async with keyring_env(tmp_path, s, clock) as e:
        first = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(8))
        second = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(5, "doc_b"))
        assert first[0].dek_id != second[0].dek_id
        rows = {r.dek_id: r for r in await e.store.list_deks(ACME)}
        assert rows[first[0].dek_id].state == DekState.RETIRED
        assert rows[second[0].dek_id].state == DekState.ACTIVE
        # old chunks still readable under the retired DEK
        out = await e.keyring.decrypt(ACME, first[0].dek_id, [
            (f, x.nonce, x.ciphertext) for (f, _), x in zip(items(8), first, strict=True)])
        assert len(out) == 8


async def test_dek_rolls_at_max_age(tmp_path: Path, settings: Settings,
                                    clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        [a] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        clock.advance(settings.dek_max_age_seconds + 1)
        [b] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        assert a.dek_id != b.dek_id


async def test_separate_deks_per_workspace_and_purpose(tmp_path: Path, settings: Settings,
                                                       clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        a = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        b = await e.keyring.encrypt(ACME, WorkspaceId("legal"), Purpose.VECTOR, items(1))
        c = await e.keyring.encrypt(ACME, WS, Purpose.VAULT, items(1))
        assert len({a[0].dek_id, b[0].dek_id, c[0].dek_id}) == 3


async def test_concurrent_first_writes_make_one_dek(tmp_path: Path, settings: Settings,
                                                    clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        res = await asyncio.gather(*(e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1, f"d{i}"))
                                     for i in range(20)))
        assert len({r[0].dek_id for r in res}) == 1


async def test_customer_disables_key(tmp_path: Path, settings: Settings,
                                     clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        [y] = await e.keyring.encrypt(BETA, WS, Purpose.VECTOR, items(1))
        await e.kms.admin("acme").disable_key(e.cmks["acme"])
        # cached key still works until TTL/flush: the documented revocation latency
        await e.keyring.decrypt(ACME, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])
        assert e.keyring.flush_tenant(ACME) >= 1
        with pytest.raises(TenantKeyUnavailableError):
            await e.keyring.decrypt(ACME, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])
        with pytest.raises(TenantKeyUnavailableError):
            await e.keyring.encrypt(ACME, WorkspaceId("new-ws"), Purpose.VECTOR, items(1))
        # beta unaffected
        e.keyring.cache.flush()
        await e.keyring.decrypt(BETA, y.dek_id, [(items(1)[0][0], y.nonce, y.ciphertext)])


async def test_revocation_takes_effect_after_ttl(tmp_path: Path, settings: Settings,
                                                 clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        await e.kms.admin("acme").disable_key(e.cmks["acme"])
        clock.advance(settings.dek_cache_ttl_seconds + 1)
        with pytest.raises(TenantKeyUnavailableError):
            await e.keyring.decrypt(ACME, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])


async def test_strict_tenant_ttl_zero_revokes_immediately(tmp_path: Path, settings: Settings,
                                                          clock: FakeClock) -> None:
    s = settings.model_copy(update={"dek_cache_ttl_seconds": 0})
    async with keyring_env(tmp_path, s, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        await e.kms.admin("acme").disable_key(e.cmks["acme"])
        with pytest.raises(TenantKeyUnavailableError):
            await e.keyring.decrypt(ACME, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])


async def test_kms_down_fails_closed(tmp_path: Path, settings: Settings,
                                     clock: FakeClock) -> None:
    import httpx

    async with keyring_env(tmp_path, settings, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        e.keyring.cache.flush()

        def refuse(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        e.provider._http = httpx.AsyncClient(transport=httpx.MockTransport(refuse),
                                             base_url="http://kms")
        with pytest.raises(DependencyUnavailableError):
            await e.keyring.decrypt(ACME, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])
        assert e.provider.calls >= 2  # retried before giving up


async def test_kms_5xx_retried_then_fails(tmp_path: Path, settings: Settings,
                                          clock: FakeClock) -> None:
    import httpx

    async with keyring_env(tmp_path, settings, clock) as e:
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        e.keyring.cache.flush()
        e.provider._http = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(503, json={})),
            base_url="http://kms")
        with pytest.raises(DependencyUnavailableError):
            await e.keyring.decrypt(ACME, x.dek_id, [(items(1)[0][0], x.nonce, x.ciphertext)])


async def test_no_plaintext_key_material_at_rest(tmp_path: Path, settings: Settings,
                                                 clock: FakeClock) -> None:
    async with keyring_env(tmp_path, settings, clock) as e:
        captured: list[bytes] = []
        await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        [x] = await e.keyring.encrypt(ACME, WS, Purpose.VECTOR, items(1))
        d = await e.store.get_dek(ACME, x.dek_id)
        assert d is not None
        await e.keyring.cache.use(ACME, x.dek_id, lambda: e.keyring._loader(d),
                                  lambda k: captured.append(bytes(k)))
        raw = b"".join(p.read_bytes() for p in settings.data_dir.glob("keyring.db*"))
        assert captured[0] not in raw


async def test_token_key_is_stable(tmp_path: Path, settings: Settings,
                                   clock: FakeClock) -> None:
    s = settings.model_copy(update={"dek_max_uses": 1})
    async with keyring_env(tmp_path, s, clock) as e:
        k1 = await e.keyring.token_key_use(ACME, bytes)
        clock.advance(settings.dek_max_age_seconds * 2)
        e.keyring.cache.flush()
        k2 = await e.keyring.token_key_use(ACME, bytes)
        kb = await e.keyring.token_key_use(BETA, bytes)
        assert k1 == k2 and k1 != kb

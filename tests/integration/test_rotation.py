"""Key rotation without downtime + compromise containment (M7)."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinel_vault.config import Settings
from sentinel_vault.domain.ids import TenantId
from sentinel_vault.kms_client.provider import GeneratedKey, TenantKeyRef
from sentinel_vault.privacy.detector import PiiDetector
from sentinel_vault.security.errors import DependencyUnavailableError
from sentinel_vault.service.rotation import RotationService
from sentinel_vault.service.tokenization import TOKEN_RE
from tests.app_env import AppEnv, app_env
from tests.conftest import FakeClock

ACME = TenantId("acme")
REC = {"fields": {"patient_name": "Johnathan Q. Marlowe", "ssn": "123-45-6789"},
       "text": "Johnathan Q. Marlowe has kidney stones. MRN: 00A-7781-22."}


@pytest.fixture
def small_deks(settings: Settings) -> Settings:
    """Roll DEKs every 2 uses so a few documents produce many DEKs to rotate."""
    return settings.model_copy(update={"dek_max_uses": 2, "job_batch_size": 3})


@pytest.fixture
async def env(tmp_path: Path, small_deks: Settings, clock: FakeClock,
              detector: PiiDetector) -> AsyncIterator[AppEnv]:
    async with app_env(tmp_path, small_deks, clock, detector) as e:
        yield e


async def _docs(env: AppEnv, tenant: str = "acme", n: int = 6) -> list[str]:
    return [(await env.ingest(tenant, {**REC, "text": f"{REC['text']} visit {i}"}))["doc_id"]
            for i in range(n)]


async def _readable(env: AppEnv, docs: list[str], tenant: str = "acme") -> bool:
    env.app.state.keyring.flush_tenant(tenant)
    for d in docs:
        r = await env.api.get(f"/documents/{d}?view=original", headers=env.h(tenant))
        if r.status_code != 200 or "Marlowe" not in r.text:
            return False
    return True


def _versions(settings: Settings, tenant: str = "acme") -> set[int]:
    with sqlite3.connect(settings.keyring_db_path) as db:
        return {v for (v,) in db.execute(
            "select cmk_version from deks where tenant_id=?", (tenant,))}


async def _cmk(env: AppEnv, tenant: str = "acme") -> str:
    row = await env.app.state.keyring.store.get_tenant_key(TenantId(tenant))
    return str(row.cmk_id)


async def test_rewrap_after_customer_rotation(env: AppEnv, small_deks: Settings) -> None:
    docs = await _docs(env)
    assert _versions(small_deks) == {1}
    await env.kms.admin("acme").rotate_key(await _cmk(env))
    assert await _readable(env, docs)  # old version still decrypts before the job
    r = await env.api.post("/tenant/keys/rewrap", headers=env.h("acme"))
    assert r.status_code == 202
    await env.app.state.rotation_service.wait()
    job = (await env.api.get(f"/tenant/jobs/{r.json()['job_id']}", headers=env.h("acme"))).json()
    assert job["state"] == "done" and job["processed"] >= 4
    assert _versions(small_deks) == {2}
    assert await _readable(env, docs)
    new = await env.ingest("acme", REC)  # new writes keep working
    assert await _readable(env, [*docs, new["doc_id"]])


async def test_reads_keep_working_during_rewrap(env: AppEnv) -> None:
    docs = await _docs(env)
    await env.kms.admin("acme").rotate_key(await _cmk(env))
    svc: RotationService = env.app.state.rotation_service
    job = asyncio.create_task(svc.start_rewrap(ACME, background=False))
    for _ in range(5):
        assert await _readable(env, docs[:2])
        r = await env.query("acme", "kidney stones", user="analyst")
        assert r.status_code == 200
        await asyncio.sleep(0)
    await job


class CrashingProvider:
    """Wraps the real provider; ReEncrypt fails after N calls (simulated crash)."""

    def __init__(self, inner: Any, fail_after: int) -> None:
        self.inner, self.left = inner, fail_after

    async def generate_data_key(self, ref: TenantKeyRef,
                                ctx: Mapping[str, str]) -> GeneratedKey:
        return await self.inner.generate_data_key(ref, ctx)  # type: ignore[no-any-return]

    async def decrypt(self, ref: TenantKeyRef, w: bytes, ctx: Mapping[str, str]) -> bytearray:
        return await self.inner.decrypt(ref, w, ctx)  # type: ignore[no-any-return]

    async def re_encrypt(self, ref: TenantKeyRef, w: bytes,
                         ctx: Mapping[str, str]) -> tuple[bytes, int]:
        if self.left <= 0:
            raise DependencyUnavailableError
        self.left -= 1
        return await self.inner.re_encrypt(ref, w, ctx)  # type: ignore[no-any-return]


async def test_rewrap_resumes_after_crash_and_restart(tmp_path: Path, small_deks: Settings,
                                                      clock: FakeClock,
                                                      detector: PiiDetector) -> None:
    async with app_env(tmp_path, small_deks, clock, detector) as env:
        docs = await _docs(env)
        await env.kms.admin("acme").rotate_key(await _cmk(env))
        kr = env.app.state.keyring
        real = kr._kms
        kr._kms = CrashingProvider(real, fail_after=4)
        svc: RotationService = env.app.state.rotation_service
        with pytest.raises(DependencyUnavailableError):
            await svc.start_rewrap(ACME, background=False)
        kr._kms = real
        assert _versions(small_deks) == {1, 2}  # half done
        assert await _readable(env, docs)        # mixed versions all readable
        # "restart": a fresh app on the same data resumes the running job on startup
    # Restart: new KMS and API processes on the same data dirs.
    from customer_kms.app import create_app as create_kms
    from customer_kms.config import KmsSettings
    from mock_llm.app import create_app as create_llm
    from sentinel_vault.api.app import create_app
    from sentinel_vault.retrieval.embedder import HashEmbedder
    kms_app = create_kms(KmsSettings(data_dir=tmp_path / "kms"), configure_logs=False,
                         clock=clock)
    async with kms_app.router.lifespan_context(kms_app):
        kms_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=kms_app),
                                     base_url="http://kms")
        llm_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_llm(False)),
                                     base_url="http://llm")
        app = create_app(small_deks, configure_logs=False, clock=clock, kms_http=kms_http,
                         service_key=env.kms.service_key, detector=detector,
                         embedder=HashEmbedder(), llm_http=llm_http)
        async with kms_http, llm_http, app.router.lifespan_context(app):
            await app.state.rotation_service.wait()
            assert _versions(small_deks) == {2}
            jobs = await app.state.keyring.store.running_jobs()
            assert jobs == []


async def test_concurrent_rewrap_rejected(env: AppEnv) -> None:
    await _docs(env, n=2)
    svc: RotationService = env.app.state.rotation_service
    await svc.start_rewrap(ACME)
    r = await env.api.post("/tenant/keys/rewrap", headers=env.h("acme"))
    assert r.status_code in (202, 409)
    await svc.wait()


async def test_rewrap_is_idempotent(env: AppEnv, small_deks: Settings) -> None:
    docs = await _docs(env, n=3)
    await env.kms.admin("acme").rotate_key(await _cmk(env))
    svc: RotationService = env.app.state.rotation_service
    await svc.start_rewrap(ACME, background=False)
    with sqlite3.connect(small_deks.keyring_db_path) as db:
        before = db.execute("select dek_id, wrapped from deks order by dek_id").fetchall()
    j = await svc.start_rewrap(ACME, background=False)
    with sqlite3.connect(small_deks.keyring_db_path) as db:
        after = db.execute("select dek_id, wrapped from deks order by dek_id").fetchall()
    assert before == after
    assert (await svc.get_job(ACME, j)).processed == 0
    assert await _readable(env, docs)


# --- containment --------------------------------------------------------------------------


def _token_of(env_text: str) -> set[str]:
    return {m.group(0) for m in TOKEN_RE.finditer(env_text)}


async def test_containment_rekeys_one_tenant(env: AppEnv, small_deks: Settings) -> None:
    docs = await _docs(env, n=4)
    beta_docs = await _docs(env, "beta", n=2)
    old_tok = (await env.api.get(f"/documents/{docs[0]}", headers=env.h("acme"))).json()
    with sqlite3.connect(small_deks.keyring_db_path) as db:
        old_deks = {d for (d,) in db.execute("select dek_id from deks where tenant_id='acme'")}
        beta_before = db.execute("select dek_id, wrapped from deks where tenant_id='beta'"
                                 " order by dek_id").fetchall()

    r = await env.api.post("/tenant/contain", headers=env.h("acme"))
    assert r.status_code == 202
    await env.app.state.rotation_service.wait()

    # every acme session was revoked; beta untouched
    assert (await env.api.get("/auth/me", headers=env.h("acme", "analyst"))).status_code == 401
    assert (await env.api.get("/auth/me", headers=env.h("beta"))).status_code == 200
    await env.relogin("acme")
    job = (await env.api.get(f"/tenant/jobs/{r.json()['job_id']}",
                             headers=env.h("acme"))).json()
    assert job["state"] == "done" and job["processed"] == 4

    with sqlite3.connect(small_deks.keyring_db_path) as db:
        now_deks = {d for (d,) in db.execute("select dek_id from deks where tenant_id='acme'")}
        beta_after = db.execute("select dek_id, wrapped from deks where tenant_id='beta'"
                                " order by dek_id").fetchall()
    assert not (old_deks & now_deks)  # old wrapped DEKs destroyed
    assert beta_before == beta_after
    with sqlite3.connect(small_deks.vector_db_path) as db:
        used = {d for (d,) in db.execute("select dek_id from chunks where tenant_id='acme' "
                                         "union select dek_id from documents "
                                         "where tenant_id='acme'")}
    assert used <= now_deks

    assert await _readable(env, docs) and await _readable(env, beta_docs, "beta")
    new_tok = (await env.api.get(f"/documents/{docs[0]}", headers=env.h("acme"))).json()
    assert _token_of(str(old_tok)) and not (_token_of(str(old_tok)) & _token_of(str(new_tok)))
    # re-identification and query work under the new token key
    q = await env.query("acme", "kidney stones", reidentify=True)
    assert q.status_code == 200
    env.llm.state.mode = "obedient"
    q = await env.query("acme", "kidney stones", reidentify=True, top_k=1)
    assert "Marlowe" in q.json()["answer"]


async def test_old_token_key_matches_nothing_after_containment(env: AppEnv) -> None:
    from sentinel_vault.service.tokenization import make_token

    await _docs(env, n=2)
    old = await env.app.state.keyring.token_key_use(ACME, bytes)  # "leaked" token key
    await env.app.state.rotation_service.start_containment(ACME, background=False)
    leaked_guess = make_token(old, "FIELD_SSN", "123-45-6789")
    assert await env.app.state.tokenizer.reidentify(ACME, [leaked_guess]) == {}


async def test_containment_blocks_tenant_while_running(env: AppEnv) -> None:
    await _docs(env, n=2)
    svc: RotationService = env.app.state.rotation_service
    gate = asyncio.Event()
    orig = svc._migrate_doc

    async def slow(*a: Any) -> None:
        await gate.wait()
        await orig(*a)

    svc._migrate_doc = slow  # type: ignore[method-assign]
    await svc.start_containment(ACME)
    login = await env.api.post("/auth/login", json={"tenant_id": "acme", "username": "admin",
                                                    "password": "correct horse battery staple"})
    assert login.status_code == 423
    assert (await env.query("beta", "kidney", user="analyst")).status_code == 200
    gate.set()
    await svc.wait()
    await env.relogin("acme")


async def test_containment_resumes_after_crash(env: AppEnv, small_deks: Settings) -> None:
    docs = await _docs(env, n=4)
    svc: RotationService = env.app.state.rotation_service
    orig = svc._migrate_doc
    calls = {"n": 0}

    async def crash_on_third(*a: Any) -> None:
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("simulated crash")
        await orig(*a)

    svc._migrate_doc = crash_on_third  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await svc.start_containment(ACME, background=False)
    svc._migrate_doc = orig  # type: ignore[method-assign]
    assert (await env.api.post("/auth/login", json={
        "tenant_id": "acme", "username": "admin",
        "password": "correct horse battery staple"})).status_code == 423  # still frozen
    assert await svc.resume_pending(background=False) == 1
    await env.relogin("acme")
    assert await _readable(env, docs)
    with sqlite3.connect(small_deks.keyring_db_path) as db:
        states = {s for (s,) in db.execute("select state from deks where tenant_id='acme'")}
    assert "compromised" not in states

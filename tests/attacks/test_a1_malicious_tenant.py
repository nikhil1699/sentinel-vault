"""A1: malicious tenant. Goal: read another tenant's data through the API.

Beta is the attacker; acme is the victim. Every attack must fail without revealing
whether the target exists.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from sentinel_vault.config import Settings
from sentinel_vault.domain.ids import DocumentId
from sentinel_vault.privacy.detector import PiiDetector
from tests.app_env import AppEnv, app_env
from tests.conftest import FakeClock

VICTIM = {"fields": {"patient_name": "Johnathan Q. Marlowe", "ssn": "123-45-6789"},
          "text": "Johnathan Q. Marlowe has kidney stones."}


@pytest.fixture
async def env(tmp_path: Path, settings: Settings, clock: FakeClock,
              detector: PiiDetector) -> AsyncIterator[AppEnv]:
    async with app_env(tmp_path, settings, clock, detector) as e:
        yield e


async def test_idor_on_document_id(env: AppEnv) -> None:
    doc = (await env.ingest("acme", VICTIM))["doc_id"]
    for view in ("tokenized", "original"):
        r = await env.api.get(f"/documents/{doc}?view={view}", headers=env.h("beta"))
        missing = await env.api.get(f"/documents/{DocumentId.new()}?view={view}",
                                    headers=env.h("beta"))
        assert r.status_code == missing.status_code == 404
        assert r.json()["error"]["message"] == missing.json()["error"]["message"]


async def test_tenant_override_attempts_ignored(env: AppEnv) -> None:
    doc = (await env.ingest("acme", VICTIM))["doc_id"]
    for extra in ({"x-tenant-id": "acme"}, {"x-kms-account": "acme"}):
        r = await env.api.get(f"/documents/{doc}?tenant_id=acme",
                              headers={**env.h("beta"), **extra})
        assert r.status_code == 404
    r = await env.api.post("/documents", headers=env.h("beta"),
                           json={**VICTIM, "tenant_id": "acme"})
    assert r.status_code == 422  # unknown field rejected, not honored


@pytest.mark.parametrize("bad_id", ["../acme", "doc_1 OR 1=1", "doc_" + "Z" * 32, "%2e%2e"])
async def test_malformed_ids(env: AppEnv, bad_id: str) -> None:
    r = await env.api.get(f"/documents/{bad_id}", headers=env.h("beta"))
    assert r.status_code in (404, 422)


async def test_onboard_with_victims_cmk(env: AppEnv) -> None:
    """Beta's admin points its tenant at acme's CMK. Acme's policy only allows tenant acme."""
    victim_cmk = await env.kms.onboard("acme")
    r = await env.api.put("/tenant/kms", headers=env.h("beta"),
                          json={"kms_account": "acme", "cmk_id": victim_cmk})
    assert r.status_code == 503
    # beta still on its own key and working
    assert (await env.ingest("beta", VICTIM))["chunks"] >= 1


async def test_row_moved_into_attacker_partition(env: AppEnv, settings: Settings) -> None:
    """With DB write access, relabel acme's document as beta's. Decryption must fail."""
    doc = (await env.ingest("acme", VICTIM))["doc_id"]
    with sqlite3.connect(settings.vector_db_path) as db:
        db.execute("update documents set tenant_id='beta' where doc_id=?", (doc,))
    with sqlite3.connect(settings.keyring_db_path) as db:
        db.execute("update deks set tenant_id='beta' where tenant_id='acme'")
    env.app.state.keyring.cache.flush()
    r = await env.api.get(f"/documents/{doc}?view=original", headers=env.h("beta"))
    assert r.status_code in (500, 503)  # KMS refuses (context says acme) or AAD fails
    assert "Marlowe" not in r.text and "123-45-6789" not in r.text


async def test_victim_tokens_useless_to_attacker(env: AppEnv) -> None:
    doc = (await env.ingest("acme", VICTIM))["doc_id"]
    r = await env.api.get(f"/documents/{doc}", headers=env.h("acme"))
    token = r.json()["fields"]["ssn"]
    from sentinel_vault.domain.ids import TenantId
    assert await env.app.state.tokenizer.reidentify(TenantId("beta"), [token]) == {}
    # Ingesting the same value in beta yields a different token: no cross-tenant linkage
    bdoc = (await env.ingest("beta", VICTIM))["doc_id"]
    rb = await env.api.get(f"/documents/{bdoc}", headers=env.h("beta"))
    assert rb.json()["fields"]["ssn"] != token

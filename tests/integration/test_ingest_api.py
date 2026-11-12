"""Store + Retrieve over HTTP, with real Presidio, real KMS, encrypted storage (M5)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from sentinel_vault.config import Settings
from sentinel_vault.domain.ids import TenantId
from sentinel_vault.privacy.detector import PiiDetector
from sentinel_vault.retrieval.chunking import decode_chunk
from sentinel_vault.service.tokenization import TOKEN_RE
from tests.app_env import AppEnv, app_env
from tests.conftest import PHI_SAMPLES, FakeClock, LogCapture

RECORD = {
    "fields": {
        "patient_name": "Johnathan Q. Marlowe",
        "ssn": "123-45-6789",
        "dob": "1984-07-19",
        "mrn": "00A-7781-22",
        "diagnosis_code": "N20.0",
        "visit_type": "follow-up",
        "notes": "Johnathan reports flank pain. Call (415) 555-0134 or "
                 "j.marlowe@example-clinic.org.",
        "insurance_carrier": "Acme Health",           # not in policy -> dropped
        "John Smith 078-05-1120": "smuggled",         # PHI in a key -> dropped
    },
    "text": "Johnathan Q. Marlowe, DOB 1984-07-19, SSN 123-45-6789, presented with kidney "
            "stones. Spouse Maria Marlowe at (415) 555-0134. MRN: 00A-7781-22.",
}
RAW_PHI = ["Johnathan", "Marlowe", "123-45-6789", "1984-07-19", "00A-7781-22", "555-0134",
           "j.marlowe@example-clinic.org", "Maria", "078-05-1120", "John Smith"]


@pytest.fixture
async def env(tmp_path: Path, settings: Settings, clock: FakeClock, detector: PiiDetector,
              logs: LogCapture) -> AsyncIterator[AppEnv]:
    async with app_env(tmp_path, settings, clock, detector) as e:
        yield e


async def test_store_and_retrieve_original(env: AppEnv) -> None:
    res = await env.ingest("acme", RECORD)
    assert res["chunks"] >= 1 and res["dropped_fields"] == 2
    assert res["tokenized_entities"]["FIELD_SSN"] == 1
    assert not any(v in json.dumps(res) for v in RAW_PHI)
    r = await env.api.get(f"/documents/{res['doc_id']}?view=original", headers=env.h("acme"))
    assert r.status_code == 200
    assert r.json()["fields"] == RECORD["fields"] and r.json()["text"] == RECORD["text"]


async def test_tokenized_view_has_no_raw_phi(env: AppEnv) -> None:
    res = await env.ingest("acme", RECORD)
    r = await env.api.get(f"/documents/{res['doc_id']}", headers=env.h("acme", "analyst"))
    body = r.json()
    assert body["view"] == "tokenized"
    dumped = json.dumps(body)
    for v in RAW_PHI:
        assert v not in dumped, v
    f = body["fields"]
    assert f["diagnosis_code"] == "N20.0" and f["visit_type"] == "follow-up"  # allowed
    assert TOKEN_RE.fullmatch(f["ssn"]) and f["ssn"].startswith("<<FIELD_SSN_")
    assert "insurance_carrier" not in f and len(f) == 7
    assert "kidney stones" in body["text"]  # clinical content survives


async def test_original_view_needs_reidentify_scope(env: AppEnv) -> None:
    res = await env.ingest("acme", RECORD)
    r = await env.api.get(f"/documents/{res['doc_id']}?view=original",
                          headers=env.h("acme", "analyst"))
    assert r.status_code == 403


async def test_scopes_enforced(env: AppEnv) -> None:
    r = await env.api.post("/documents", json=RECORD, headers=env.h("acme", "analyst"))
    assert r.status_code == 403
    r = await env.api.put("/tenant/policy", json={}, headers=env.h("acme", "loader"))
    assert r.status_code == 403
    assert (await env.api.post("/documents", json=RECORD)).status_code == 401


async def test_same_value_same_token_within_tenant_not_across(env: AppEnv) -> None:
    a1 = await env.ingest("acme", RECORD)
    a2 = await env.ingest("acme", RECORD)
    b1 = await env.ingest("beta", RECORD)

    async def ssn_token(t: str, doc: str) -> str:
        r = await env.api.get(f"/documents/{doc}", headers=env.h(t))
        return str(r.json()["fields"]["ssn"])

    assert await ssn_token("acme", a1["doc_id"]) == await ssn_token("acme", a2["doc_id"])
    assert await ssn_token("acme", a1["doc_id"]) != await ssn_token("beta", b1["doc_id"])


async def test_vault_reidentifies_for_own_tenant_only(env: AppEnv) -> None:
    res = await env.ingest("acme", RECORD)
    r = await env.api.get(f"/documents/{res['doc_id']}", headers=env.h("acme"))
    toks = TOKEN_RE.findall(r.json()["text"])
    tokens = [f"<<{e}_{h}>>" for e, h in toks]
    tz = env.app.state.tokenizer
    mine = await tz.reidentify(TenantId("acme"), tokens)
    assert "123-45-6789" in mine.values()
    assert await tz.reidentify(TenantId("beta"), tokens) == {}


async def test_nothing_raw_at_rest(env: AppEnv, settings: Settings) -> None:
    await env.ingest("acme", RECORD)
    raw = b"".join(p.read_bytes() for p in settings.data_dir.glob("*.db*"))
    raw += b"".join(p.read_bytes() for p in env.kms.data_dir.rglob("*.db*"))
    for v in RAW_PHI + ["kidney stones", "flank pain"]:
        assert v.encode() not in raw, v


async def test_decrypted_chunks_and_embeddings_are_tokenized(env: AppEnv) -> None:
    res = await env.ingest("acme", RECORD)
    store = env.app.state.ingest_service._store
    kr = env.app.state.keyring
    rows = await store.list_chunks(TenantId("acme"))
    assert rows and all(r.doc_id == res["doc_id"] for r in rows)
    pts = await kr.decrypt(TenantId("acme"), rows[0].dek_id, [
        ({"doc_id": r.doc_id, "chunk_id": r.chunk_id, "seq": r.seq, "kind": "chunk"},
         r.nonce, r.ciphertext) for r in rows])
    for pt in pts:
        text, vec = decode_chunk(pt)
        assert vec.shape == (256,)
        for v in RAW_PHI:
            assert v not in text, v


async def test_not_onboarded_tenant(tmp_path: Path, settings: Settings, clock: FakeClock,
                                    detector: PiiDetector) -> None:
    async with app_env(tmp_path, settings, clock, detector, onboard=False) as e:
        r = await e.api.post("/documents", json=RECORD, headers=e.h("acme"))
        assert r.status_code == 409 and r.json()["error"]["code"] == "tenant_not_onboarded"


async def test_onboarding_rejects_bad_cmk(env: AppEnv) -> None:
    other = await env.kms.admin("beta").create_key()  # beta's key, acme's admin
    r = await env.api.put("/tenant/kms", headers=env.h("acme"),
                          json={"kms_account": "beta", "cmk_id": other})
    assert r.status_code == 503 and r.json()["error"]["code"] == "tenant_key_unavailable"


async def test_default_policy_drops_unknown_fields(tmp_path: Path, settings: Settings,
                                                   clock: FakeClock,
                                                   detector: PiiDetector) -> None:
    async with app_env(tmp_path, settings, clock, detector) as e:
        await e.api.put("/tenant/policy", headers=e.h("acme"), json={})
        res = await e.ingest("acme", {"fields": {"anything": "x", "ssn": "1"}, "text": None})
        assert res["dropped_fields"] == 2 and res["chunks"] == 0


async def test_input_limits(env: AppEnv, settings: Settings) -> None:
    big = "a " * (settings.max_text_chars // 2 + 1)
    r = await env.api.post("/documents", json={"text": big}, headers=env.h("acme"))
    assert r.status_code == 400
    many = {f"f{i}": "x" for i in range(settings.max_fields + 1)}
    r = await env.api.post("/documents", json={"fields": many}, headers=env.h("acme"))
    assert r.status_code == 400
    r = await env.api.post("/documents", json={"fields": {"x": {"nested": 1}}},
                           headers=env.h("acme"))
    assert r.status_code == 422


async def test_detector_outage_fails_closed(env: AppEnv) -> None:
    from sentinel_vault.privacy.detector import PiiDetector as Det

    class Broken:
        def analyze(self, text: str, language: str, score_threshold: float) -> list[object]:
            raise RuntimeError("down")

    svc = env.app.state.ingest_service
    good = svc._det
    svc._det = Det(Broken(), 0.35)
    try:
        r = await env.api.post("/documents", json=RECORD, headers=env.h("acme"))
        assert r.status_code == 503 and r.json()["error"]["code"] == "detection_unavailable"
        store = svc._store
        assert await store.count_documents(TenantId("acme")) == 0
    finally:
        svc._det = good


async def test_no_phi_in_logs_or_responses(env: AppEnv, logs: LogCapture) -> None:
    res = await env.ingest("acme", RECORD)
    await env.api.get(f"/documents/{res['doc_id']}", headers=env.h("acme"))
    await env.api.post("/documents", json={**RECORD, "bogus": 1}, headers=env.h("acme"))
    for v in RAW_PHI + list(PHI_SAMPLES.values()):
        assert v not in logs.text, v


async def test_concurrent_ingest_ten_tenants(tmp_path: Path, settings: Settings,
                                             clock: FakeClock, detector: PiiDetector) -> None:
    tenants = tuple(f"tenant-{i:02d}" for i in range(10))
    async with app_env(tmp_path, settings, clock, detector, tenants) as e:
        results = await asyncio.gather(*(e.ingest(t, RECORD) for t in tenants for _ in range(2)))
        assert len({r["doc_id"] for r in results}) == 20
        store = e.app.state.ingest_service._store
        for t in tenants:
            assert await store.count_documents(TenantId(t)) == 2


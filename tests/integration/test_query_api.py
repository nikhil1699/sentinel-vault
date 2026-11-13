"""Process: agentic RAG query across the PHI boundary (M6)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from sentinel_vault.config import Settings
from sentinel_vault.privacy.detector import PiiDetector
from tests.app_env import AppEnv, app_env
from tests.conftest import FakeClock, LogCapture

PATIENTS = [
    {"fields": {"patient_name": "Johnathan Q. Marlowe", "ssn": "123-45-6789",
                "diagnosis_code": "N20.0"},
     "text": "Johnathan Q. Marlowe presented with kidney stones. Call (415) 555-0134."},
    {"fields": {"patient_name": "Priya Raman", "ssn": "234-56-7890",
                "diagnosis_code": "S52.5"},
     "text": "Priya Raman fractured her left wrist while cycling. Email priya@example.org."},
    {"fields": {"patient_name": "Alan Grant", "ssn": "345-67-8901",
                "diagnosis_code": "J45.9"},
     "text": "Alan Grant has asthma, uses an inhaler daily. MRN: 00B-1234-55."},
]
RAW = ["Johnathan", "Marlowe", "123-45-6789", "555-0134", "Priya", "Raman", "234-56-7890",
       "priya@example.org", "Alan Grant", "345-67-8901", "00B-1234-55"]


@pytest.fixture
async def env(tmp_path: Path, settings: Settings, clock: FakeClock, detector: PiiDetector,
              logs: LogCapture) -> AsyncIterator[AppEnv]:
    async with app_env(tmp_path, settings, clock, detector) as e:
        for p in PATIENTS:
            await e.ingest("acme", p)
        yield e


async def test_query_answers_from_tokenized_context(env: AppEnv) -> None:
    r = await env.query("acme", "Who has kidney stones?", user="analyst")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sources"] and "kidney stones" in body["answer"]
    assert body["reidentified"] is False
    for v in RAW:
        assert v not in r.text and v not in env.llm_received(), v


async def test_pii_in_question_is_tokenized_and_still_matches(env: AppEnv) -> None:
    r = await env.query("acme", "Priya Raman", top_k=1)
    body = r.json()
    assert "wrist" in body["answer"]  # name token in question matched stored token
    assert "Priya" not in env.llm_received()


async def test_reidentify_needs_scope(env: AppEnv) -> None:
    r = await env.query("acme", "Who has kidney stones?", user="analyst", reidentify=True)
    assert r.status_code == 403
    assert env.llm_received() == ""  # refused before anything left


async def test_reidentify_restores_own_values_locally(env: AppEnv) -> None:
    env.llm.state.mode = "obedient"
    r = await env.query("acme", "Who has kidney stones?", top_k=1, reidentify=True)
    body = r.json()
    assert body["reidentified"] and "Johnathan Q. Marlowe" in body["answer"]
    assert "Marlowe" not in env.llm_received()  # only our side saw the real name


async def test_kms_calls_per_query(env: AppEnv) -> None:
    provider = env.app.state.keyring._kms
    env.app.state.keyring.flush_tenant("acme")
    before = provider.calls
    await env.query("acme", "asthma inhaler", top_k=3)
    first = provider.calls - before
    before = provider.calls
    await env.query("acme", "asthma inhaler", top_k=3)
    assert first <= 3 and provider.calls == before  # vector DEK + token key; then cached


async def test_retrieval_is_tenant_scoped(env: AppEnv) -> None:
    await env.ingest("beta", {"fields": {}, "text": "Beta-only secret: zebra protocol."})
    r = await env.query("acme", "zebra protocol", top_k=20)
    assert "Beta-only" not in r.json()["answer"] and "Beta-only" not in env.llm_received()


async def test_empty_workspace(env: AppEnv) -> None:
    r = await env.query("acme", "anything", workspace_id="empty-ws")
    assert r.json()["sources"] == [] and env.llm_received() == ""


async def test_input_limits(env: AppEnv, settings: Settings) -> None:
    assert (await env.query("acme", "x" * (settings.query_max_chars + 1))).status_code == 400
    assert (await env.query("acme", "x", top_k=settings.query_max_top_k + 1)).status_code == 400
    assert (await env.query("acme", "")).status_code == 422


async def test_llm_down_fails_closed(env: AppEnv) -> None:
    env.llm.state.mode = "error"
    r = await env.query("acme", "kidney stones")
    assert r.status_code == 503 and r.json()["error"]["code"] == "llm_unavailable"


async def test_detector_down_sends_nothing(env: AppEnv) -> None:
    from sentinel_vault.privacy.detector import PiiDetector as Det

    class Broken:
        def analyze(self, text: str, language: str, score_threshold: float) -> list[object]:
            raise RuntimeError("down")

    qs = env.app.state.query_service
    qs._guard._det = Det(Broken(), 0.35)
    r = await env.query("acme", "kidney")
    assert r.status_code == 503 and env.llm_received() == ""


async def test_customer_revokes_key_query_stops(env: AppEnv) -> None:
    cmk = (await env.app.state.keyring.store.get_tenant_key("acme")).cmk_id
    await env.kms.admin("acme").disable_key(cmk)
    r = await env.api.post("/tenant/cache/flush", headers=env.h("acme"))
    assert r.json()["evicted"] >= 1
    r = await env.query("acme", "kidney")
    assert r.status_code == 503 and r.json()["error"]["code"] == "tenant_key_unavailable"


async def test_no_phi_in_logs(env: AppEnv, logs: LogCapture) -> None:
    env.llm.state.mode = "obedient"
    await env.query("acme", "What about Johnathan Q. Marlowe, SSN 123-45-6789?",
                    reidentify=True)
    for v in RAW:
        assert v not in logs.text, v


async def test_concurrent_queries_ten_tenants(tmp_path: Path, settings: Settings,
                                              clock: FakeClock, detector: PiiDetector) -> None:
    tenants = tuple(f"tenant-{i:02d}" for i in range(10))
    async with app_env(tmp_path, settings, clock, detector, tenants) as e:
        words = dict(zip(tenants, ["apple", "banana", "cherry", "grape", "lemon", "mango",
                                   "olive", "peach", "plum", "melon"], strict=True))
        for t in tenants:
            await e.ingest(t, {"fields": {}, "text": f"Our ward stocks {words[t]} juice."})
        rs = await asyncio.gather(*(e.query(t, "juice", user="analyst")
                                    for t in tenants for _ in range(3)))
        for i, r in enumerate(rs):
            t = tenants[i // 3]
            assert r.status_code == 200
            ctx = r.json()["answer"].split("<question>")[0]
            assert words[t] in ctx
            assert not any(w in ctx for o, w in words.items() if o != t)

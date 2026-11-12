"""A2: storage insider with read/write access to our databases (not the KMS).

Goal: read or silently alter customer data. Reads must yield only ciphertext; any
alteration must be detected, never served.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from sentinel_vault.config import Settings
from sentinel_vault.privacy.detector import PiiDetector
from tests.app_env import AppEnv, app_env
from tests.conftest import FakeClock

REC = {"fields": {"patient_name": "Johnathan Q. Marlowe", "ssn": "123-45-6789"},
       "text": "Johnathan Q. Marlowe, MRN: 00A-7781-22, has kidney stones."}


@pytest.fixture
async def env(tmp_path: Path, settings: Settings, clock: FakeClock,
              detector: PiiDetector) -> AsyncIterator[AppEnv]:
    async with app_env(tmp_path, settings, clock, detector) as e:
        yield e


async def _get(env: AppEnv, doc: str, view: str = "original") -> tuple[int, str]:
    env.app.state.keyring.cache.flush()
    r = await env.api.get(f"/documents/{doc}?view={view}", headers=env.h("acme"))
    return r.status_code, r.text


async def test_raw_db_read_yields_nothing(env: AppEnv, settings: Settings) -> None:
    await env.ingest("acme", REC)
    blob = b"".join(p.read_bytes() for p in settings.data_dir.glob("*.db*"))
    for v in ("Marlowe", "123-45-6789", "00A-7781-22", "kidney"):
        assert v.encode() not in blob


@pytest.mark.parametrize("column", ["original_ct", "original_nonce"])
async def test_bit_flip_detected(env: AppEnv, settings: Settings, column: str) -> None:
    doc = (await env.ingest("acme", REC))["doc_id"]
    with sqlite3.connect(settings.vector_db_path) as db:
        v = bytearray(db.execute(f"select {column} from documents where doc_id=?",  # noqa: S608
                                 (doc,)).fetchone()[0])
        v[3] ^= 0x10
        db.execute(f"update documents set {column}=? where doc_id=?", (bytes(v), doc))  # noqa: S608
    status, text = await _get(env, doc)
    assert status == 500 and "integrity_error" in text and "Marlowe" not in text


async def test_swap_ciphertexts_between_documents(env: AppEnv, settings: Settings) -> None:
    """Put doc A's ciphertext under doc B's id (same tenant, same DEK). AAD has doc_id."""
    a = (await env.ingest("acme", REC))["doc_id"]
    b = (await env.ingest("acme", {**REC, "text": "Other patient, unrelated."}))["doc_id"]
    with sqlite3.connect(settings.vector_db_path) as db:
        n, c = db.execute("select original_nonce, original_ct from documents where doc_id=?",
                          (a,)).fetchone()
        db.execute("update documents set original_nonce=?, original_ct=? where doc_id=?",
                   (n, c, b))
    status, _ = await _get(env, b)
    assert status == 500


async def test_swap_original_and_tokenized(env: AppEnv, settings: Settings) -> None:
    """Serve the raw original where the tokenized view is expected. AAD has the kind."""
    doc = (await env.ingest("acme", REC))["doc_id"]
    with sqlite3.connect(settings.vector_db_path) as db:
        db.execute("update documents set tokenized_nonce=original_nonce, "
                   "tokenized_ct=original_ct where doc_id=?", (doc,))
    r = await env.api.get(f"/documents/{doc}", headers=env.h("acme", "analyst"))
    assert r.status_code == 500 and "Marlowe" not in r.text


async def test_point_row_at_other_dek(env: AppEnv, settings: Settings) -> None:
    a = (await env.ingest("acme", REC))["doc_id"]
    await env.ingest("acme", {**REC, "workspace_id": "legal"})  # different DEK
    with sqlite3.connect(settings.keyring_db_path) as db:
        other = db.execute("select dek_id from deks where workspace_id='legal' "
                           "and purpose='document'").fetchone()[0]
    with sqlite3.connect(settings.vector_db_path) as db:
        db.execute("update documents set dek_id=? where doc_id=?", (other, a))
    status, _ = await _get(env, a)
    assert status == 500


async def test_vault_value_swap_detected(env: AppEnv, settings: Settings) -> None:
    """Swap two vault entries so one token would re-identify to the other's value."""
    await env.ingest("acme", REC)
    with sqlite3.connect(settings.vault_db_path) as db:
        rows = db.execute("select token, nonce, ciphertext from vault_entries "
                          "where tenant_id='acme' limit 2").fetchall()
        (t1, n1, c1), (t2, n2, c2) = rows
        db.execute("update vault_entries set nonce=?, ciphertext=? where token=?", (n2, c2, t1))
    from sentinel_vault.domain.ids import TenantId
    from sentinel_vault.kms_client.provider import DataIntegrityError
    env.app.state.keyring.cache.flush()
    with pytest.raises(DataIntegrityError):
        await env.app.state.tokenizer.reidentify(TenantId("acme"), [t1])


async def test_stolen_dbs_without_kms_are_useless(env: AppEnv, settings: Settings) -> None:
    """Insider has all our DBs and the service key, but the customer disabled the CMK."""
    doc = (await env.ingest("acme", REC))["doc_id"]
    await env.kms.admin("acme").disable_key(await _cmk(settings))
    status, text = await _get(env, doc)
    assert status == 503 and "Marlowe" not in text


async def _cmk(settings: Settings) -> str:
    with sqlite3.connect(settings.keyring_db_path) as db:
        return str(db.execute("select cmk_id from tenant_keys where tenant_id='acme'")
                   .fetchone()[0])

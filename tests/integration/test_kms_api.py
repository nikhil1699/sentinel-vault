"""Customer KMS end to end over HTTP (BYOK handshake, data keys, rotation, lifecycle)."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from customer_kms.client import KmsError
from customer_kms.policy import CryptoAction
from tests.conftest import FakeClock, LogCapture
from tests.kms_env import KmsEnv, ctx, kms_env, tenant_policy


@pytest.fixture
async def env(tmp_path: Path, clock: FakeClock, logs: LogCapture) -> AsyncIterator[KmsEnv]:
    async with kms_env(tmp_path, clock) as e:
        yield e


async def test_onboarding_handshake_and_roundtrip(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc = env.service("acme")
    dk = await svc.generate_data_key(cmk, ctx("acme"))
    assert len(dk.plaintext) == 32 and dk.cmk_version == 1
    assert bytes(dk.plaintext) not in dk.ciphertext_blob
    assert await svc.decrypt(dk.ciphertext_blob, ctx("acme")) == dk.plaintext


async def test_new_key_denies_us_until_customer_grants(env: KmsEnv) -> None:
    cmk = await env.admin("acme").create_key()
    with pytest.raises(KmsError) as ei:
        await env.service("acme").generate_data_key(cmk, ctx("acme"))
    assert ei.value.code == "access_denied"


async def test_wrong_context_cannot_decrypt(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc = env.service("acme")
    dk = await svc.generate_data_key(cmk, ctx("acme"))
    with pytest.raises(KmsError) as ei:
        await svc.decrypt(dk.ciphertext_blob, ctx("acme", workspace_id="other"))
    assert ei.value.code == "invalid_ciphertext"


async def test_policy_tenant_condition_enforced_by_customer(env: KmsEnv) -> None:
    """Even if our code asks for tenant beta's context on acme's key, acme's policy says no."""
    cmk = await env.onboard("acme")
    with pytest.raises(KmsError) as ei:
        await env.service("acme").generate_data_key(cmk, ctx("beta"))
    assert ei.value.code == "access_denied"


async def test_service_cannot_do_admin_ops(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc = env.service("acme")
    for call in (svc.create_key(), svc.put_key_policy(cmk, tenant_policy("acme")),
                 svc.rotate_key(cmk), svc.disable_key(cmk), svc.get_key_policy(cmk),
                 svc.schedule_key_deletion(cmk), svc.list_audit()):
        with pytest.raises(KmsError) as ei:
            await call
        assert ei.value.code == "access_denied"


async def test_rotation_old_blobs_still_decrypt(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc, admin = env.service("acme"), env.admin("acme")
    old = await svc.generate_data_key(cmk, ctx("acme"))
    assert await admin.rotate_key(cmk) == 2
    new = await svc.generate_data_key(cmk, ctx("acme"))
    assert new.cmk_version == 2
    assert await svc.decrypt(old.ciphertext_blob, ctx("acme")) == old.plaintext
    assert await svc.decrypt(new.ciphertext_blob, ctx("acme")) == new.plaintext
    assert (await admin.describe_key(cmk))["current_version"] == 2


async def test_re_encrypt_moves_to_current_version(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc = env.service("acme")
    old = await svc.generate_data_key(cmk, ctx("acme"))
    await env.admin("acme").rotate_key(cmk)
    blob2, v = await svc.re_encrypt(old.ciphertext_blob, ctx("acme"))
    assert v == 2 and blob2 != old.ciphertext_blob
    assert await svc.decrypt(blob2, ctx("acme")) == old.plaintext


async def test_re_encrypt_needs_its_own_grant(env: KmsEnv) -> None:
    admin = env.admin("acme")
    cmk = await admin.create_key()
    await admin.put_key_policy(cmk, tenant_policy(
        "acme", actions=[CryptoAction.GENERATE_DATA_KEY, CryptoAction.DECRYPT]))
    svc = env.service("acme")
    dk = await svc.generate_data_key(cmk, ctx("acme"))
    with pytest.raises(KmsError) as ei:
        await svc.re_encrypt(dk.ciphertext_blob, ctx("acme"))
    assert ei.value.code == "access_denied"


async def test_disable_is_a_kill_switch_and_enable_restores(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc, admin = env.service("acme"), env.admin("acme")
    dk = await svc.generate_data_key(cmk, ctx("acme"))
    await admin.disable_key(cmk)
    for call in (svc.decrypt(dk.ciphertext_blob, ctx("acme")),
                 svc.generate_data_key(cmk, ctx("acme")),
                 svc.re_encrypt(dk.ciphertext_blob, ctx("acme"))):
        with pytest.raises(KmsError) as ei:
            await call
        assert ei.value.code == "key_unavailable"
    with pytest.raises(KmsError):
        await admin.rotate_key(cmk)
    await admin.enable_key(cmk)
    assert await svc.decrypt(dk.ciphertext_blob, ctx("acme")) == dk.plaintext


async def test_scheduled_deletion_crypto_shreds(env: KmsEnv, clock: FakeClock) -> None:
    cmk = await env.onboard("acme")
    svc, admin = env.service("acme"), env.admin("acme")
    dk = await svc.generate_data_key(cmk, ctx("acme"))
    with pytest.raises(KmsError):
        await admin.schedule_key_deletion(cmk, pending_days=1)  # below 7-day floor
    await admin.schedule_key_deletion(cmk, pending_days=7)
    with pytest.raises(KmsError):
        await svc.decrypt(dk.ciphertext_blob, ctx("acme"))
    clock.advance(7 * 86_400 + 1)
    assert (await admin.describe_key(cmk))["state"] == "Destroyed"
    with sqlite3.connect(env.data_dir / "accounts/acme/kms.db") as db:
        assert db.execute("select count(*) from key_versions where cmk_id=?",
                          (cmk,)).fetchone()[0] == 0
    with pytest.raises(KmsError):
        await admin.cancel_key_deletion(cmk)
    with pytest.raises(KmsError) as ei:
        await svc.decrypt(dk.ciphertext_blob, ctx("acme"))
    assert ei.value.code == "key_unavailable"


async def test_cancel_deletion_returns_disabled(env: KmsEnv, clock: FakeClock) -> None:
    cmk = await env.onboard("acme")
    admin = env.admin("acme")
    await admin.schedule_key_deletion(cmk, pending_days=7)
    clock.advance(86_400)
    await admin.cancel_key_deletion(cmk)
    assert (await admin.describe_key(cmk))["state"] == "Disabled"
    clock.advance(30 * 86_400)
    await admin.enable_key(cmk)
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    assert len(dk.plaintext) == 32


async def test_accounts_are_isolated(env: KmsEnv) -> None:
    acme_cmk = await env.onboard("acme")
    beta_cmk = await env.onboard("beta")
    acme_blob = (await env.service("acme").generate_data_key(acme_cmk, ctx("acme")))
    # beta's admin can't see acme's key; our service on beta's account can't open acme's blob
    with pytest.raises(KmsError):
        await env.admin("beta").describe_key(acme_cmk)
    with pytest.raises(KmsError) as ei:
        await env.service("beta").decrypt(acme_blob.ciphertext_blob, ctx("acme"))
    assert ei.value.code == "access_denied"
    with pytest.raises(KmsError):
        await env.service("beta").generate_data_key(acme_cmk, ctx("beta"))
    # beta's own key still works
    dk = await env.service("beta").generate_data_key(beta_cmk, ctx("beta"))
    assert await env.service("beta").decrypt(dk.ciphertext_blob, ctx("beta")) == dk.plaintext


async def test_audit_records_allows_and_denies_without_secrets(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc = env.service("acme")
    dk = await svc.generate_data_key(cmk, ctx("acme"))
    with pytest.raises(KmsError):
        await svc.generate_data_key(cmk, ctx("beta"))
    entries = await env.admin("acme").list_audit()
    ops = [(e["operation"], e["principal"], e["outcome"]) for e in entries]
    assert ("GenerateDataKey", "sentinel-svc", "allow") in ops
    assert ("GenerateDataKey", "sentinel-svc", "deny") in ops
    deny = next(e for e in entries if e["outcome"] == "deny")
    assert deny["reason"] == "implicit_deny"
    assert deny["encryption_context"]["tenant_id"] == "beta"
    from customer_kms.protocol import b64e
    assert b64e(dk.plaintext) not in str(entries)
    assert await env.admin("acme").verify_audit()


async def test_audit_tamper_detected(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    await env.service("acme").generate_data_key(cmk, ctx("acme"))
    db_path = env.data_dir / "accounts/acme/kms.db"
    with sqlite3.connect(db_path) as db:
        db.execute("update audit set outcome='deny' where operation='GenerateDataKey'")
    assert await env.admin("acme").verify_audit() is False


async def test_plaintext_keys_never_logged(env: KmsEnv, logs: LogCapture) -> None:
    from customer_kms.protocol import b64e

    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    pt = await env.service("acme").decrypt(dk.ciphertext_blob, ctx("acme"))
    assert b64e(pt) not in logs.text
    assert b64e(dk.ciphertext_blob) not in logs.text


async def test_root_key_and_db_are_private(env: KmsEnv) -> None:
    await env.onboard("acme")
    acct = env.data_dir / "accounts/acme"
    for f in ("root.key", "kms.db", "account.json"):
        assert (acct / f).stat().st_mode & 0o077 == 0, f
    assert acct.stat().st_mode & 0o077 == 0


async def test_cmk_material_not_stored_in_plaintext(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    with sqlite3.connect(env.data_dir / "accounts/acme/kms.db") as db:
        sealed = db.execute("select sealed_material from key_versions where cmk_id=?",
                            (cmk,)).fetchone()[0]
    assert len(sealed) == 12 + 32 + 16  # nonce + sealed key + tag


async def test_concurrent_data_keys_across_tenants(tmp_path: Path, clock: FakeClock) -> None:
    accounts = tuple(f"tenant-{i:02d}" for i in range(10))
    async with kms_env(tmp_path, clock, accounts) as env:
        cmks = {a: await env.onboard(a) for a in accounts}

        async def roundtrip(a: str) -> bool:
            svc = env.service(a)
            dk = await svc.generate_data_key(cmks[a], ctx(a))
            return await svc.decrypt(dk.ciphertext_blob, ctx(a)) == dk.plaintext

        results = await asyncio.gather(*(roundtrip(a) for a in accounts for _ in range(5)))
        assert all(results) and len(results) == 50


async def test_bad_requests_rejected(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    svc = env.service("acme")
    for op, payload in [
        ("GenerateDataKey", {"cmk_id": "not-a-key", "encryption_context": {}}),
        ("GenerateDataKey", {"cmk_id": cmk, "encryption_context": {"BAD KEY": "x"}}),
        ("Decrypt", {"ciphertext_blob": "@@@@@@@@@@", "encryption_context": {}}),
        ("Decrypt", {"ciphertext_blob": "AAAAAAAAAAAA", "encryption_context": {},
                     "extra": 1}),
        ("NoSuchOp", {}),
    ]:
        with pytest.raises(KmsError) as ei:
            await svc.call(op, payload)
        assert ei.value.status in (400, 404, 422), op


async def test_unknown_key_looks_like_denied(env: KmsEnv) -> None:
    await env.onboard("acme")
    with pytest.raises(KmsError) as ei:
        await env.service("acme").generate_data_key("cmk_" + "0" * 32, ctx("acme"))
    assert ei.value.code == "access_denied"

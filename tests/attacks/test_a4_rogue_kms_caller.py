"""A4: rogue KMS caller.

Goal: use (or abuse) access to a customer's key outside what the customer allowed.
Each test is one attack. Every one must fail and leave an audit trace where possible.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from customer_kms.client import KmsClient, KmsError
from customer_kms.protocol import H_SIGNATURE, b64e, sign_request
from tests.conftest import FakeClock
from tests.kms_env import SERVICE, KmsEnv, ctx, kms_env


@pytest.fixture
async def env(tmp_path: Path, clock: FakeClock) -> AsyncIterator[KmsEnv]:
    async with kms_env(tmp_path, clock) as e:
        yield e


async def _raw(env: KmsEnv, headers: dict[str, str], body: bytes,
               path: str = "/v1/Decrypt") -> int:
    r = await env.http.post(path, content=body,
                            headers={**headers, "content-type": "application/json"})
    return r.status_code


async def _signed_decrypt(env: KmsEnv, blob: bytes, key: Ed25519PrivateKey,
                          principal: str = SERVICE, account: str = "acme",
                          now: float | None = None, nonce: str | None = None
                          ) -> tuple[dict[str, str], bytes]:
    body = json.dumps({"ciphertext_blob": b64e(blob),
                       "encryption_context": ctx("acme")}).encode()
    h = sign_request(key, method="POST", path="/v1/Decrypt", account=account,
                     principal=principal, body=body, now=now if now is not None else env.clock(),
                     nonce=nonce)
    return h, body


async def test_replay_of_captured_request(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    h, body = await _signed_decrypt(env, dk.ciphertext_blob, env.service_key)
    assert await _raw(env, h, body) == 200
    assert await _raw(env, h, body) == 401  # same nonce: replay rejected


async def test_replay_after_restart_within_window(env: KmsEnv, tmp_path: Path,
                                                  clock: FakeClock) -> None:
    """Nonces are persisted, so a KMS restart doesn't reopen the replay window."""
    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    h, body = await _signed_decrypt(env, dk.ciphertext_blob, env.service_key)
    assert await _raw(env, h, body) == 200
    import httpx

    from customer_kms.app import create_app
    from customer_kms.config import KmsSettings
    app2 = create_app(KmsSettings(data_dir=env.data_dir), configure_logs=False, clock=clock)
    async with app2.router.lifespan_context(app2):
        t = httpx.ASGITransport(app=app2)
        async with httpx.AsyncClient(transport=t, base_url="http://kms") as http2:
            r = await http2.post("/v1/Decrypt", content=body,
                                 headers={**h, "content-type": "application/json"})
            assert r.status_code == 401


async def test_stale_or_future_request(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    for skew in (-61, 61, -3600):
        h, body = await _signed_decrypt(env, dk.ciphertext_blob, env.service_key,
                                        now=env.clock() + skew)
        assert await _raw(env, h, body) == 401


async def test_body_swap_under_valid_signature(env: KmsEnv) -> None:
    """Attacker re-uses signed headers but changes the context in the body."""
    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    h, _ = await _signed_decrypt(env, dk.ciphertext_blob, env.service_key)
    evil = json.dumps({"ciphertext_blob": b64e(dk.ciphertext_blob),
                       "encryption_context": ctx("beta")}).encode()
    assert await _raw(env, h, evil) == 401


async def test_path_swap_under_valid_signature(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    h, body = await _signed_decrypt(env, dk.ciphertext_blob, env.service_key)
    assert await _raw(env, h, body, path="/v1/ReEncrypt") == 401


async def test_forged_principal_and_admin_impersonation(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    mallory = Ed25519PrivateKey.generate()
    for principal in (SERVICE, "acme-admin", "unknown-svc"):
        c = KmsClient(env.http, account="acme", principal=principal, private_key=mallory,
                      clock=env.clock)
        with pytest.raises(KmsError) as ei:
            await c.generate_data_key(cmk, ctx("acme"))
        assert ei.value.status == 401
    # our service key can't act as the customer's admin
    c = KmsClient(env.http, account="acme", principal="acme-admin",
                  private_key=env.service_key, clock=env.clock)
    with pytest.raises(KmsError) as ei:
        await c.rotate_key(cmk)
    assert ei.value.status == 401


async def test_signature_garbage(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    h, body = await _signed_decrypt(env, dk.ciphertext_blob, env.service_key)
    for bad in ("", "AAAA", "not base64!!", h[H_SIGNATURE][:-4] + "AAAA"):
        assert await _raw(env, {**h, H_SIGNATURE: bad}, body) == 401
    assert await _raw(env, {}, body) == 401
    assert await _raw(env, {**h, "x-kms-account": "../acme"}, body) == 401


async def test_cross_tenant_context_on_own_access(env: KmsEnv) -> None:
    """A bug (or attacker) in our service asks for beta's data under acme's key."""
    acme = await env.onboard("acme")
    for c in (ctx("beta"), {"tenant_id": "acme"}, {}):
        with pytest.raises(KmsError) as ei:
            await env.service("acme").generate_data_key(acme, c)
        assert ei.value.code == "access_denied"


async def test_blob_from_other_account_rejected(env: KmsEnv) -> None:
    beta = await env.onboard("beta")
    blob = (await env.service("beta").generate_data_key(beta, ctx("beta"))).ciphertext_blob
    await env.onboard("acme")
    with pytest.raises(KmsError) as ei:
        await env.service("acme").decrypt(blob, ctx("beta"))
    assert ei.value.code == "access_denied"


async def test_version_downgrade_in_blob(env: KmsEnv) -> None:
    """Rewrite a v2 blob header to claim v1: AAD binds the header, so it fails."""
    from customer_kms import crypto

    cmk = await env.onboard("acme")
    await env.admin("acme").rotate_key(cmk)
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    header, hb, body = crypto.parse_blob(dk.ciphertext_blob)
    forged = crypto.BlobHeader(header.account, header.cmk_id, 1).encode() + body
    with pytest.raises(KmsError) as ei:
        await env.service("acme").decrypt(forged, ctx("acme"))
    assert ei.value.code == "invalid_ciphertext"


async def test_every_attack_leaves_audit_trace(env: KmsEnv) -> None:
    cmk = await env.onboard("acme")
    dk = await env.service("acme").generate_data_key(cmk, ctx("acme"))
    h, body = await _signed_decrypt(env, dk.ciphertext_blob, env.service_key)
    await _raw(env, h, body)
    await _raw(env, h, body)  # replay
    with pytest.raises(KmsError):
        await env.service("acme").generate_data_key(cmk, ctx("beta"))
    reasons = {(e["operation"], e["reason"]) for e in await env.admin("acme").list_audit()}
    assert ("Authenticate", "replay") in reasons
    assert ("GenerateDataKey", "implicit_deny") in reasons

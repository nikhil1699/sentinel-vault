"""Auth over HTTP: the authorization boundary as a client sees it."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sentinel_vault.api.app import create_app
from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import Scope
from sentinel_vault.domain.ids import TenantId, UserId
from sentinel_vault.security.sensitive import Sensitive
from sentinel_vault.service.auth_service import AuthService
from tests.conftest import FakeClock, LogCapture

PASSWORD = "correct horse battery staple"


@pytest.fixture
async def app(settings: Settings, clock: FakeClock, logs: LogCapture,
              app_deps: dict[str, Any]) -> AsyncIterator[FastAPI]:
    app = create_app(settings, configure_logs=False, clock=clock, **app_deps)
    async with app.router.lifespan_context(app):
        svc: AuthService = app.state.auth_service
        for t in ("acme", "beta"):
            await svc.create_tenant(TenantId(t))
            await svc.create_user(TenantId(t), UserId("alice"), Sensitive(PASSWORD),
                                  [Scope.QUERY])
        yield app


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _login(c: httpx.AsyncClient, tenant: str = "acme") -> str:
    r = await c.post("/auth/login", json={"tenant_id": tenant, "username": "alice",
                                          "password": PASSWORD})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert isinstance(token, str)
    return token


def _h(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


async def test_login_me_logout(client: httpx.AsyncClient) -> None:
    r = await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                               "password": PASSWORD})
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["scopes"] == ["query"]
    me = (await client.get("/auth/me", headers=_h(body["token"]))).json()
    assert me["tenant_id"] == "acme" and me["session_id"] == body["session_id"]
    assert (await client.post("/auth/logout", headers=_h(body["token"]))).status_code == 204
    assert (await client.get("/auth/me", headers=_h(body["token"]))).status_code == 401


async def test_many_parallel_sessions_over_http(client: httpx.AsyncClient) -> None:
    tokens = await asyncio.gather(*(_login(client, t) for t in ("acme", "beta") for _ in range(4)))
    mes = await asyncio.gather(*(client.get("/auth/me", headers=_h(t)) for t in tokens))
    assert [m.json()["tenant_id"] for m in mes] == ["acme"] * 4 + ["beta"] * 4
    listed = (await client.get("/auth/sessions", headers=_h(tokens[0]))).json()
    assert len(listed) == 4
    assert sum(s["current"] for s in listed) == 1
    for t in tokens:
        assert t not in str(listed)


async def test_all_auth_failures_same_response(client: httpx.AsyncClient,
                                               clock: FakeClock) -> None:
    good = await _login(client)
    revoked = await _login(client)
    await client.post("/auth/logout", headers=_h(revoked))
    expired = await _login(client)
    clock.advance(1801)
    await client.get("/auth/me", headers=_h(good))  # also expired now
    cases = [
        {},
        {"authorization": "Basic YWxpY2U6cHc="},
        {"authorization": "Bearer"},
        {"authorization": "Bearer garbage"},
        _h(revoked),
        _h(expired),
    ]
    bodies = []
    for headers in cases:
        r = await client.get("/auth/me", headers=headers)
        assert r.status_code == 401, headers
        e = r.json()["error"]
        bodies.append((e["code"], e["message"]))
    assert len(set(bodies)) == 1


async def test_wrong_password_and_unknown_user_same(client: httpx.AsyncClient) -> None:
    a = await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                               "password": "wrong-password-123"})
    b = await client.post("/auth/login", json={"tenant_id": "acme", "username": "nobody",
                                               "password": "wrong-password-123"})
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


async def test_body_tenant_cannot_override_session(client: httpx.AsyncClient) -> None:
    token = await _login(client, "acme")
    r = await client.get("/auth/me?tenant_id=beta",
                         headers={**_h(token), "x-tenant-id": "beta"})
    assert r.json()["tenant_id"] == "acme"


async def test_extra_login_fields_rejected(client: httpx.AsyncClient) -> None:
    r = await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                               "password": PASSWORD, "scopes": ["admin"]})
    assert r.status_code == 422


async def test_passwords_and_tokens_never_logged(client: httpx.AsyncClient,
                                                 logs: LogCapture) -> None:
    token = await _login(client)
    await client.get("/auth/me", headers=_h(token))
    await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                           "password": "wrong-password-xyz"})
    await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                           "password": 123})  # validation error
    for secret in (PASSWORD, token, token[4:], "wrong-password-xyz"):
        assert secret not in logs.text


async def test_validation_error_does_not_echo_password(client: httpx.AsyncClient) -> None:
    pw = "Sup3r-secret-but-too-long" * 20
    r = await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                               "password": pw})
    assert r.status_code == 422
    assert pw not in r.text


async def test_rate_limit_status(client: httpx.AsyncClient, settings: Settings) -> None:
    for _ in range(settings.login_max_failures):
        await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                               "password": "wrong-password-123"})
    r = await client.post("/auth/login", json={"tenant_id": "acme", "username": "alice",
                                               "password": PASSWORD})
    assert r.status_code == 429


async def test_logout_all_and_revoke_specific(client: httpx.AsyncClient) -> None:
    a, b, c = await _login(client), await _login(client), await _login(client)
    sid_b = (await client.get("/auth/me", headers=_h(b))).json()["session_id"]
    assert (await client.delete(f"/auth/sessions/{sid_b}", headers=_h(a))).status_code == 204
    assert (await client.get("/auth/me", headers=_h(b))).status_code == 401
    r = await client.post("/auth/logout-all", headers=_h(c))
    assert r.json() == {"revoked": 2}
    assert (await client.get("/auth/me", headers=_h(a))).status_code == 401


async def test_revoke_other_tenants_session_is_404(client: httpx.AsyncClient) -> None:
    beta = await _login(client, "beta")
    sid = (await client.get("/auth/me", headers=_h(beta))).json()["session_id"]
    acme = await _login(client, "acme")
    r = await client.delete(f"/auth/sessions/{sid}", headers=_h(acme))
    assert r.status_code == 404
    assert (await client.get("/auth/me", headers=_h(beta))).status_code == 200

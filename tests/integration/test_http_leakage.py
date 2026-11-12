"""F5 leakage prevention at the HTTP boundary: errors and logs never carry input data."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from customer_kms.app import create_app as create_kms
from mock_llm.app import create_app as create_llm
from sentinel_vault.api.app import create_app
from sentinel_vault.config import Settings
from sentinel_vault.security.errors import (
    AuthenticationError,
    DependencyUnavailableError,
    NotFoundError,
    PolicyViolationError,
)
from tests.conftest import PHI_SAMPLES, LogCapture

ALL_PHI = list(PHI_SAMPLES.values())


class Intake(BaseModel):
    age: int
    tenant: str


def _app(settings: Settings) -> FastAPI:
    app = create_app(settings, configure_logs=False)

    @app.post("/_t/boom")
    async def boom(body: dict[str, str]) -> None:
        raise RuntimeError(f"failed processing {body}")

    @app.post("/_t/intake")
    async def intake(body: Intake) -> Intake:
        return body

    @app.get("/_t/app-error/{kind}")
    async def app_error(kind: str) -> None:
        raise {"notfound": NotFoundError, "auth": AuthenticationError,
               "policy": PolicyViolationError, "dep": DependencyUnavailableError}[kind]()

    return app


@pytest.fixture
async def client(settings: Settings, logs: LogCapture) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_app(settings), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _assert_clean(text: str) -> None:
    for v in ALL_PHI:
        assert v not in text, f"leaked: {v!r}"


async def test_unhandled_exception_with_phi(client: httpx.AsyncClient, logs: LogCapture) -> None:
    r = await client.post("/_t/boom", json=PHI_SAMPLES)
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "internal_error"
    assert r.json()["error"]["message"] == "Internal error."
    _assert_clean(r.text)
    _assert_clean(logs.text)
    assert "RuntimeError" in logs.text  # still debuggable
    rid = r.headers["x-request-id"]
    assert r.json()["error"]["request_id"] == rid
    assert any(rec.get("request_id") == rid for rec in logs.records())


async def test_validation_error_does_not_echo_input(client: httpx.AsyncClient,
                                                    logs: LogCapture) -> None:
    payload = {"age": PHI_SAMPLES["ssn"], "tenant": 5,
               PHI_SAMPLES["name"]: PHI_SAMPLES["email"]}
    r = await client.post("/_t/intake", json=payload)
    assert r.status_code == 422
    body = r.json()["error"]
    assert body["code"] == "validation_error"
    assert {"loc": ["body", "age"], "type": "int_parsing"} in body["fields"]
    _assert_clean(r.text)
    _assert_clean(logs.text)


async def test_phi_shaped_field_name_hidden(client: httpx.AsyncClient) -> None:
    r = await client.post("/_t/intake", json={PHI_SAMPLES["ssn"]: 1})
    assert r.status_code == 422
    # missing fields reported by name; unknown keys never echoed
    _assert_clean(r.text)


async def test_malformed_json(client: httpx.AsyncClient, logs: LogCapture) -> None:
    raw = '{"age": 1, "tenant": "' + PHI_SAMPLES["ssn"] + '"'  # truncated JSON
    r = await client.post("/_t/intake", content=raw,
                          headers={"content-type": "application/json"})
    assert r.status_code == 422
    _assert_clean(r.text)
    _assert_clean(logs.text)


@pytest.mark.parametrize(
    ("kind", "status", "code"),
    [("notfound", 404, "not_found"), ("auth", 401, "unauthenticated"),
     ("policy", 422, "policy_violation"), ("dep", 503, "dependency_unavailable")],
)
async def test_app_errors_have_fixed_messages(client: httpx.AsyncClient, kind: str,
                                              status: int, code: str) -> None:
    r = await client.get(f"/_t/app-error/{kind}")
    assert r.status_code == status
    assert r.json()["error"]["code"] == code


async def test_unknown_route_and_method(client: httpx.AsyncClient, logs: LogCapture) -> None:
    r = await client.get(f"/patients/{PHI_SAMPLES['ssn']}?email={PHI_SAMPLES['email']}")
    assert r.status_code == 404
    assert r.json()["error"]["message"] == "Not found."
    r2 = await client.delete("/health")
    assert r2.status_code == 405
    _assert_clean(r.text + r2.text)
    _assert_clean(logs.text)
    access = [rec for rec in logs.records() if rec.get("event") == "request"]
    assert access and all(rec["route"] in ("unmatched", "/health") for rec in access)


async def test_security_headers_and_request_id(client: httpx.AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "sentinel-api"}
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    uuid.UUID(r.headers["x-request-id"])


async def test_inbound_request_id_must_be_uuid(client: httpx.AsyncClient) -> None:
    good = str(uuid.uuid4())
    r = await client.get("/health", headers={"x-request-id": good})
    assert r.headers["x-request-id"] == good
    evil = 'x"\n{"level":"critical","event":"forged"}'
    r2 = await client.get("/health", headers={"x-request-id": evil.replace("\n", " ")})
    assert r2.headers["x-request-id"] != evil
    uuid.UUID(r2.headers["x-request-id"])


@pytest.mark.parametrize(
    ("factory", "service"),
    [(lambda: create_kms(configure_logs=False), "customer-kms"),
     (lambda: create_llm(configure_logs=False), "mock-llm")],
)
async def test_other_services_share_protections(factory: object, service: str) -> None:
    app = factory()  # type: ignore[operator]
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/health")
        assert r.json()["service"] == service
        assert r.headers["cache-control"] == "no-store"
        r404 = await c.get(f"/x/{PHI_SAMPLES['ssn']}")
        assert r404.status_code == 404
        _assert_clean(r404.text)

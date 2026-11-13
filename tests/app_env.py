"""Full stack in-process: Sentinel API + customer KMS, onboarded tenants, logged-in users."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI

from mock_llm.app import create_app as create_llm
from sentinel_vault.api.app import create_app
from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import Scope
from sentinel_vault.domain.ids import TenantId, UserId
from sentinel_vault.privacy.detector import PiiDetector
from sentinel_vault.privacy.policy import DataPolicy, FieldAction
from sentinel_vault.retrieval.embedder import HashEmbedder
from sentinel_vault.security.sensitive import Sensitive
from sentinel_vault.service.auth_service import AuthService
from tests.conftest import FakeClock
from tests.kms_env import KmsEnv, kms_env

PASSWORD = "correct horse battery staple"

CLINIC_POLICY = DataPolicy(fields={
    "patient_name": FieldAction.TOKENIZE, "ssn": FieldAction.TOKENIZE,
    "dob": FieldAction.TOKENIZE, "mrn": FieldAction.TOKENIZE,
    "diagnosis_code": FieldAction.ALLOW, "visit_type": FieldAction.ALLOW,
    "notes": FieldAction.SCAN,
})


@dataclass
class AppEnv:
    app: FastAPI
    api: httpx.AsyncClient
    kms: KmsEnv
    llm: FastAPI
    tokens: dict[tuple[str, str], str] = field(default_factory=dict)

    def h(self, tenant: str, user: str = "admin") -> dict[str, str]:
        return {"authorization": f"Bearer {self.tokens[(tenant, user)]}"}

    async def ingest(self, tenant: str, body: dict[str, Any], user: str = "admin") -> Any:
        r = await self.api.post("/documents", json=body, headers=self.h(tenant, user))
        assert r.status_code == 201, r.text
        return r.json()

    async def query(self, tenant: str, question: str, user: str = "admin",
                    **kw: Any) -> httpx.Response:
        return await self.api.post("/query", json={"question": question, **kw},
                                   headers=self.h(tenant, user))

    def llm_received(self) -> str:
        """Everything the external LLM ever received, as one string."""
        return "\n".join(m.content for r in self.llm.state.received for m in r.messages)

    async def relogin(self, tenant: str, user: str = "admin") -> None:
        r = await self.api.post("/auth/login", json={"tenant_id": tenant, "username": user,
                                                     "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.tokens[(tenant, user)] = r.json()["token"]


@asynccontextmanager
async def app_env(tmp_path: Path, settings: Settings, clock: FakeClock, detector: PiiDetector,
                  tenants: tuple[str, ...] = ("acme", "beta"),
                  onboard: bool = True) -> AsyncIterator[AppEnv]:
    async with kms_env(tmp_path, clock, tenants) as kms:
        llm = create_llm(configure_logs=False)
        llm_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=llm),
                                     base_url="http://llm")
        app = create_app(settings, configure_logs=False, clock=clock, kms_http=kms.http,
                         service_key=kms.service_key, detector=detector,
                         embedder=HashEmbedder(), llm_http=llm_http)
        async with llm_http, app.router.lifespan_context(app):
            auth: AuthService = app.state.auth_service
            users = {"admin": list(Scope), "analyst": [Scope.QUERY],
                     "loader": [Scope.INGEST, Scope.QUERY]}
            for t in tenants:
                await auth.create_tenant(TenantId(t))
                for u, scopes in users.items():
                    await auth.create_user(TenantId(t), UserId(u), Sensitive(PASSWORD), scopes)
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://api") as api:
                env = AppEnv(app, api, kms, llm)
                for t in tenants:
                    for u in users:
                        r = await api.post("/auth/login", json={
                            "tenant_id": t, "username": u, "password": PASSWORD})
                        env.tokens[(t, u)] = r.json()["token"]
                    if onboard:
                        cmk = await kms.onboard(t)
                        r = await api.put("/tenant/kms", headers=env.h(t),
                                          json={"kms_account": t, "cmk_id": cmk})
                        assert r.status_code == 200, r.text
                        r = await api.put("/tenant/policy", headers=env.h(t),
                                          json=CLINIC_POLICY.model_dump(mode="json"))
                        assert r.status_code == 200, r.text
                yield env

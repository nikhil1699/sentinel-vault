"""Shared KMS test environment: two customer accounts, our service principal, clients."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from customer_kms.app import create_app
from customer_kms.client import KmsClient
from customer_kms.config import KmsSettings
from customer_kms.directory import create_account, register_principal
from customer_kms.policy import CryptoAction, KeyPolicy, Statement
from tests.conftest import FakeClock

SERVICE = "sentinel-svc"


def pub_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def tenant_policy(tenant: str, principal: str = SERVICE,
                  actions: list[CryptoAction] | None = None) -> KeyPolicy:
    return KeyPolicy(statements=[Statement(
        sid="AllowSentinel", effect="Allow", principals=[principal],
        actions=actions or list(CryptoAction),
        condition={"encryption_context_equals": {"tenant_id": tenant},  # type: ignore[arg-type]
                   "encryption_context_keys": ["purpose"]},
    )])


@dataclass
class KmsEnv:
    app: FastAPI
    http: httpx.AsyncClient
    data_dir: Path
    clock: FakeClock
    service_key: Ed25519PrivateKey
    admin_keys: dict[str, Ed25519PrivateKey]

    def admin(self, account: str) -> KmsClient:
        return KmsClient(self.http, account=account, principal=f"{account}-admin",
                         private_key=self.admin_keys[account], clock=self.clock)

    def service(self, account: str) -> KmsClient:
        return KmsClient(self.http, account=account, principal=SERVICE,
                         private_key=self.service_key, clock=self.clock)

    async def onboard(self, account: str, tenant: str | None = None) -> str:
        """Customer creates a CMK and grants our service access scoped to its tenant."""
        admin = self.admin(account)
        cmk = await admin.create_key(f"{account} RAG key")
        await admin.put_key_policy(cmk, tenant_policy(tenant or account))
        return cmk


def ctx(tenant: str, **extra: str) -> dict[str, str]:
    return {"tenant_id": tenant, "workspace_id": "default", "purpose": "vector", **extra}


@asynccontextmanager
async def kms_env(tmp_path: Path, clock: FakeClock,
                  accounts: tuple[str, ...] = ("acme", "beta")) -> AsyncIterator[KmsEnv]:
    data_dir = tmp_path / "kms"
    service_key = Ed25519PrivateKey.generate()
    register_principal(data_dir, SERVICE, pub_pem(service_key))
    admin_keys = {}
    for a in accounts:
        admin_keys[a] = Ed25519PrivateKey.generate()
        create_account(data_dir, a, pub_pem(admin_keys[a]))
    app = create_app(KmsSettings(data_dir=data_dir), configure_logs=False, clock=clock)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://kms") as http:
            yield KmsEnv(app, http, data_dir, clock, service_key, admin_keys)

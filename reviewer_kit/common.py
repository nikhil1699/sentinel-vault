"""Shared plumbing for seed / demo / attack / simulate.

A ``Stack`` is the three services plus two operator-side handles:

- ``auth``: our operator path for creating tenants and users (there is deliberately no
  public signup API).
- ``kms_data_dir``: the cloud provider's account signup (``customer_kms.directory``).

Live runs build it from the running services (``live_stack``). Tests build it in-process
with ASGI transports, so the exact same code is exercised in both.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from customer_kms.client import KmsClient
from customer_kms.config import KmsSettings
from customer_kms.directory import create_account, load_account
from customer_kms.policy import CryptoAction, KeyPolicy, Statement
from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import Scope
from sentinel_vault.domain.ids import TenantId, UserId
from sentinel_vault.persistence.auth_store import AuthStore
from sentinel_vault.persistence.sqlite import create_sqlite_engine
from sentinel_vault.privacy.policy import DataPolicy, FieldAction
from sentinel_vault.security.errors import ConflictError
from sentinel_vault.security.files import ensure_private_dir, write_exclusive
from sentinel_vault.security.sensitive import Sensitive
from sentinel_vault.service.auth_service import AuthService

USERS: dict[str, list[Scope]] = {
    "admin": list(Scope),
    "analyst": [Scope.QUERY],
    "loader": [Scope.INGEST, Scope.QUERY],
}

CLINIC_POLICY = DataPolicy(fields={
    "patient_name": FieldAction.TOKENIZE, "ssn": FieldAction.TOKENIZE,
    "dob": FieldAction.TOKENIZE, "mrn": FieldAction.TOKENIZE,
    "phone": FieldAction.TOKENIZE, "email": FieldAction.TOKENIZE,
    "diagnosis_code": FieldAction.ALLOW, "visit_type": FieldAction.ALLOW,
    "notes": FieldAction.SCAN,
})


def tenant_key_policy(tenant: str, principal: str) -> KeyPolicy:
    """The policy a customer attaches to their CMK: our service, their tenant only."""
    return KeyPolicy(statements=[Statement(
        sid="AllowSentinelForThisTenant", effect="Allow", principals=[principal],
        actions=list(CryptoAction),
        condition={"encryption_context_equals": {"tenant_id": tenant},
                   "encryption_context_keys": ["purpose"]})])


@dataclass
class Stack:
    api: httpx.AsyncClient
    kms: httpx.AsyncClient
    llm: httpx.AsyncClient
    auth: AuthService
    kms_data_dir: Path
    sentinel_data_dir: Path
    secrets_dir: Path
    service_principal: str
    service_key: Ed25519PrivateKey


@dataclass
class Customer:
    tenant: str
    cmk_id: str
    passwords: dict[str, str]
    admin_key: Ed25519PrivateKey = field(repr=False)
    tokens: dict[str, str] = field(default_factory=dict, repr=False)

    def kms_admin(self, stack: Stack) -> KmsClient:
        return KmsClient(stack.kms, account=self.tenant, principal=f"{self.tenant}-admin",
                         private_key=self.admin_key)

    def h(self, user: str = "admin") -> dict[str, str]:
        return {"authorization": f"Bearer {self.tokens[user]}"}

    async def login(self, stack: Stack, user: str = "admin") -> str:
        r = await stack.api.post("/auth/login", json={
            "tenant_id": self.tenant, "username": user, "password": self.passwords[user]})
        r.raise_for_status()
        self.tokens[user] = str(r.json()["token"])
        return self.tokens[user]


def _customer_dir(stack: Stack, tenant: str) -> Path:
    return ensure_private_dir(stack.secrets_dir / "customers" / tenant)


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_customer(stack: Stack, tenant: str) -> Customer | None:
    d = stack.secrets_dir / "customers" / tenant
    if not (d / "state.json").is_file():
        return None
    st = json.loads((d / "state.json").read_text())
    key = serialization.load_pem_private_key((d / "admin.pem").read_bytes(), password=None)
    assert isinstance(key, Ed25519PrivateKey)  # noqa: S101
    return Customer(tenant, st["cmk_id"], st["passwords"], key)


async def provision_customer(stack: Stack, tenant: str,
                             policy: DataPolicy = CLINIC_POLICY) -> Customer:
    """Full BYOK onboarding for one customer. Idempotent via ``state.json``."""
    existing = load_customer(stack, tenant)
    if existing is not None:
        return existing
    d = _customer_dir(stack, tenant)

    # 1. Customer signs up with their key provider (cloud account + admin identity).
    admin_key = Ed25519PrivateKey.generate()
    if load_account(stack.kms_data_dir, tenant) is None:
        create_account(stack.kms_data_dir, tenant, admin_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        write_exclusive(d / "admin.pem", _pem(admin_key), 0o600)
    else:  # pragma: no cover - half-provisioned earlier run
        raise ConflictError

    # 2. We (operator) create the tenant and its users with random passwords.
    passwords = {u: secrets.token_urlsafe(18) for u in USERS}
    await stack.auth.create_tenant(TenantId(tenant))
    for u, scopes in USERS.items():
        await stack.auth.create_user(TenantId(tenant), UserId(u), Sensitive(passwords[u]),
                                     scopes)

    # 3. Customer creates a CMK and grants our service access for their tenant only.
    c = Customer(tenant, "", passwords, admin_key)
    kms = c.kms_admin(stack)
    c.cmk_id = await kms.create_key(f"{tenant} RAG master key")
    await kms.put_key_policy(c.cmk_id, tenant_key_policy(tenant, stack.service_principal))

    # 4. Tenant admin registers the CMK with us (we probe it) and sets the data policy.
    await c.login(stack)
    r = await stack.api.put("/tenant/kms", headers=c.h(),
                            json={"kms_account": tenant, "cmk_id": c.cmk_id})
    r.raise_for_status()
    r = await stack.api.put("/tenant/policy", headers=c.h(), json=policy.model_dump(mode="json"))
    r.raise_for_status()
    write_exclusive(d / "state.json", json.dumps(
        {"cmk_id": c.cmk_id, "passwords": passwords}).encode(), 0o600)
    return c


@asynccontextmanager
async def live_stack() -> AsyncIterator[Stack]:
    """Connect to the services started by ``./run.sh`` (loopback only)."""
    s, ks = Settings(), KmsSettings()
    key = serialization.load_pem_private_key(s.service_private_key_path.read_bytes(),
                                             password=None)
    assert isinstance(key, Ed25519PrivateKey)  # noqa: S101
    engine = create_sqlite_engine(s.auth_db_path)
    store = AuthStore(engine)
    await store.create_schema()
    timeout = httpx.Timeout(60.0)
    async with (httpx.AsyncClient(base_url=f"http://127.0.0.1:{s.api_port}", timeout=timeout)
                as api,
                httpx.AsyncClient(base_url=s.kms_url, timeout=timeout) as kms,
                httpx.AsyncClient(base_url=s.llm_url, timeout=timeout) as llm):
        try:
            yield Stack(api, kms, llm, AuthService(store, s), ks.data_dir, s.data_dir,
                        s.secrets_dir, s.service_principal, key)
        finally:
            await engine.dispose()


def disposable(prefix: str) -> str:
    """A fresh tenant id for one demo/attack run, so seeded tenants are never touched."""
    return f"{prefix}-{secrets.token_hex(3)}"


async def llm_received(stack: Stack) -> list[str]:
    r = await stack.llm.get("/v1/received")
    r.raise_for_status()
    return [m["content"] for req in r.json()["requests"] for m in req["messages"]]


async def set_llm_mode(stack: Stack, mode: str) -> None:
    (await stack.llm.put("/v1/mode", json={"mode": mode})).raise_for_status()


def jprint(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)

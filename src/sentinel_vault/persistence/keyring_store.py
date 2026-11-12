"""``keyring.db``: tenant -> customer CMK mapping, wrapped DEKs, tenant data policies.

Kept apart from ``vector.db`` / ``vault.db``: a copy of the data stores alone doesn't
even contain the wrapped DEKs. (Both together are still useless without the KMS.)
Every lookup is scoped by ``tenant_id``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import (
    Column,
    Float,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    and_,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel_vault.domain.ids import DekId, TenantId, WorkspaceId

metadata = MetaData()

tenant_keys = Table(
    "tenant_keys", metadata,
    Column("tenant_id", String(32), primary_key=True),
    Column("kms_account", String(64), nullable=False),
    Column("cmk_id", String(40), nullable=False),
    Column("created_at", Float, nullable=False),
)

deks = Table(
    "deks", metadata,
    Column("dek_id", String(40), primary_key=True),
    Column("tenant_id", String(32), nullable=False),
    Column("workspace_id", String(32), nullable=False),
    Column("purpose", String(16), nullable=False),
    Column("wrapped", LargeBinary, nullable=False),
    Column("cmk_version", Integer, nullable=False),
    Column("uses", Integer, nullable=False, default=0),
    Column("created_at", Float, nullable=False),
    Column("state", String(16), nullable=False),
    Index("ix_deks_active", "tenant_id", "workspace_id", "purpose", "state"),
)

policies = Table(
    "policies", metadata,
    Column("tenant_id", String(32), primary_key=True),
    Column("policy_json", Text, nullable=False),
    Column("updated_at", Float, nullable=False),
)


class DekState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    COMPROMISED = "compromised"


class Purpose(StrEnum):
    DOCUMENT = "document"
    VECTOR = "vector"
    VAULT = "vault"
    TOKEN_KEY = "tokenkey"  # noqa: S105 - a purpose label, not a secret


@dataclass(frozen=True, slots=True)
class TenantKeyRow:
    tenant_id: TenantId
    kms_account: str
    cmk_id: str


@dataclass(frozen=True, slots=True)
class DekRow:
    dek_id: DekId
    tenant_id: TenantId
    workspace_id: WorkspaceId
    purpose: Purpose
    wrapped: bytes
    cmk_version: int
    uses: int
    created_at: float
    state: DekState


def _dek(r: object) -> DekRow:
    m = r._mapping  # type: ignore[attr-defined]
    return DekRow(DekId(m["dek_id"]), TenantId(m["tenant_id"]), WorkspaceId(m["workspace_id"]),
                  Purpose(m["purpose"]), bytes(m["wrapped"]), int(m["cmk_version"]),
                  int(m["uses"]), float(m["created_at"]), DekState(m["state"]))


class KeyringStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def create_schema(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    # --- tenant -> CMK ---------------------------------------------------------------

    async def set_tenant_key(self, row: TenantKeyRow, now: float) -> None:
        async with self._engine.begin() as conn:
            existing = (await conn.execute(select(tenant_keys.c.tenant_id).where(
                tenant_keys.c.tenant_id == row.tenant_id))).first()
            values = {"kms_account": row.kms_account, "cmk_id": row.cmk_id}
            if existing:
                await conn.execute(update(tenant_keys)
                                   .where(tenant_keys.c.tenant_id == row.tenant_id)
                                   .values(**values))
            else:
                await conn.execute(tenant_keys.insert().values(
                    tenant_id=row.tenant_id, created_at=now, **values))

    async def get_tenant_key(self, tenant_id: TenantId) -> TenantKeyRow | None:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(tenant_keys).where(
                tenant_keys.c.tenant_id == tenant_id))).first()
        if r is None:
            return None
        m = r._mapping
        return TenantKeyRow(TenantId(m["tenant_id"]), m["kms_account"], m["cmk_id"])

    # --- DEKs --------------------------------------------------------------------------

    async def active_dek(self, tenant_id: TenantId, workspace_id: WorkspaceId,
                         purpose: Purpose) -> DekRow | None:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(deks).where(and_(
                deks.c.tenant_id == tenant_id, deks.c.workspace_id == workspace_id,
                deks.c.purpose == purpose, deks.c.state == DekState.ACTIVE))
                .order_by(deks.c.created_at.desc()).limit(1))).first()
        return None if r is None else _dek(r)

    async def insert_dek(self, row: DekRow, retire: DekId | None = None) -> None:
        """Insert a new active DEK; retire the previous one in the same transaction."""
        async with self._engine.begin() as conn:
            if retire is not None:
                await conn.execute(update(deks).where(and_(
                    deks.c.dek_id == retire, deks.c.tenant_id == row.tenant_id))
                    .values(state=DekState.RETIRED))
            await conn.execute(deks.insert().values(
                dek_id=row.dek_id, tenant_id=row.tenant_id, workspace_id=row.workspace_id,
                purpose=row.purpose, wrapped=row.wrapped, cmk_version=row.cmk_version,
                uses=row.uses, created_at=row.created_at, state=row.state))

    async def get_dek(self, tenant_id: TenantId, dek_id: DekId) -> DekRow | None:
        """Tenant-scoped: another tenant's dek_id returns None."""
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(deks).where(and_(
                deks.c.dek_id == dek_id, deks.c.tenant_id == tenant_id)))).first()
        return None if r is None else _dek(r)

    async def add_uses(self, tenant_id: TenantId, dek_id: DekId, n: int) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(update(deks).where(and_(
                deks.c.dek_id == dek_id, deks.c.tenant_id == tenant_id))
                .values(uses=deks.c.uses + n))

    async def set_dek_state(self, tenant_id: TenantId, dek_id: DekId, state: DekState) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(update(deks).where(and_(
                deks.c.dek_id == dek_id, deks.c.tenant_id == tenant_id)).values(state=state))

    async def list_deks(self, tenant_id: TenantId) -> list[DekRow]:
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(deks).where(deks.c.tenant_id == tenant_id)
                                       .order_by(deks.c.created_at))).all()
        return [_dek(r) for r in rows]

    # --- tenant data policies -----------------------------------------------------------

    async def set_policy(self, tenant_id: TenantId, policy_json: str, now: float) -> None:
        async with self._engine.begin() as conn:
            existing = (await conn.execute(select(policies.c.tenant_id).where(
                policies.c.tenant_id == tenant_id))).first()
            if existing:
                await conn.execute(update(policies).where(policies.c.tenant_id == tenant_id)
                                   .values(policy_json=policy_json, updated_at=now))
            else:
                await conn.execute(policies.insert().values(
                    tenant_id=tenant_id, policy_json=policy_json, updated_at=now))

    async def get_policy(self, tenant_id: TenantId) -> str | None:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(policies.c.policy_json).where(
                policies.c.tenant_id == tenant_id))).first()
        return None if r is None else str(r[0])

"""``vault.db``: token -> encrypted original value, per tenant."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import (
    Column,
    Float,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    and_,
    select,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel_vault.domain.ids import DekId, TenantId

metadata = MetaData()

vault_entries = Table(
    "vault_entries", metadata,
    Column("tenant_id", String(32), nullable=False),
    Column("token", String(80), nullable=False),
    Column("entity", String(48), nullable=False),
    Column("dek_id", String(40), nullable=False),
    Column("nonce", LargeBinary, nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    Column("created_at", Float, nullable=False),
    PrimaryKeyConstraint("tenant_id", "token"),
)


@dataclass(frozen=True, slots=True)
class VaultRow:
    tenant_id: TenantId
    token: str
    entity: str
    dek_id: DekId
    nonce: bytes
    ciphertext: bytes


class VaultStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def create_schema(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def existing_tokens(self, tenant_id: TenantId, tokens: list[str]) -> set[str]:
        if not tokens:
            return set()
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(vault_entries.c.token).where(and_(
                vault_entries.c.tenant_id == tenant_id,
                vault_entries.c.token.in_(tokens))))).scalars().all()
        return set(rows)

    async def insert_many(self, rows: list[VaultRow], now: float) -> None:
        """Idempotent: an existing (tenant, token) is left as is."""
        if not rows:
            return
        stmt = sqlite_insert(vault_entries).on_conflict_do_nothing(
            index_elements=["tenant_id", "token"])
        async with self._engine.begin() as conn:
            await conn.execute(stmt, [
                {"tenant_id": r.tenant_id, "token": r.token, "entity": r.entity,
                 "dek_id": r.dek_id, "nonce": r.nonce, "ciphertext": r.ciphertext,
                 "created_at": now} for r in rows])

    async def get_many(self, tenant_id: TenantId, tokens: list[str]) -> list[VaultRow]:
        if not tokens:
            return []
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(vault_entries).where(and_(
                vault_entries.c.tenant_id == tenant_id,
                vault_entries.c.token.in_(tokens))))).all()
        return [VaultRow(TenantId(m["tenant_id"]), m["token"], m["entity"], DekId(m["dek_id"]),
                         bytes(m["nonce"]), bytes(m["ciphertext"]))
                for m in (r._mapping for r in rows)]

    async def rows_on_deks(self, tenant_id: TenantId, dek_ids: list[str]) -> list[VaultRow]:
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(vault_entries).where(and_(
                vault_entries.c.tenant_id == tenant_id,
                vault_entries.c.dek_id.in_(dek_ids))))).all()
        return [VaultRow(TenantId(m["tenant_id"]), m["token"], m["entity"], DekId(m["dek_id"]),
                         bytes(m["nonce"]), bytes(m["ciphertext"]))
                for m in (r._mapping for r in rows)]

    async def delete_on_deks(self, tenant_id: TenantId, dek_ids: list[str]) -> int:
        async with self._engine.begin() as conn:
            res = await conn.execute(vault_entries.delete().where(and_(
                vault_entries.c.tenant_id == tenant_id,
                vault_entries.c.dek_id.in_(dek_ids))))
        return int(res.rowcount)

    async def entities(self, tenant_id: TenantId, prefix: str) -> list[str]:
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(vault_entries.c.entity).distinct().where(and_(
                vault_entries.c.tenant_id == tenant_id,
                vault_entries.c.entity.startswith(prefix))))).scalars().all()
        return sorted(rows)

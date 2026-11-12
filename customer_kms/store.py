"""Per-account KMS storage: keys, sealed key versions, used nonces, audit chain."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Column,
    Float,
    Integer,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    and_,
    delete,
    func,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

metadata = MetaData()

keys = Table(
    "keys", metadata,
    Column("cmk_id", String(40), primary_key=True),
    Column("description", String(256), nullable=False),
    Column("state", String(20), nullable=False),
    Column("policy_json", Text, nullable=False),
    Column("created_at", Float, nullable=False),
    Column("deletion_date", Float, nullable=True),
)

key_versions = Table(
    "key_versions", metadata,
    Column("cmk_id", String(40), nullable=False),
    Column("version", Integer, nullable=False),
    Column("sealed_material", LargeBinary, nullable=False),
    Column("created_at", Float, nullable=False),
    PrimaryKeyConstraint("cmk_id", "version"),
)

nonces = Table(
    "nonces", metadata,
    Column("principal", String(64), nullable=False),
    Column("nonce", String(32), nullable=False),
    Column("expires_at", Float, nullable=False, index=True),
    PrimaryKeyConstraint("principal", "nonce"),
)

audit = Table(
    "audit", metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("ts", Float, nullable=False),
    Column("principal", String(64), nullable=False),
    Column("operation", String(32), nullable=False),
    Column("cmk_id", String(40), nullable=True),
    Column("outcome", String(8), nullable=False),
    Column("reason", String(64), nullable=False),
    Column("context_json", Text, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("entry_hash", String(64), nullable=False),
)

GENESIS = "0" * 64


class KeyState(StrEnum):
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    PENDING_DELETION = "PendingDeletion"
    DESTROYED = "Destroyed"


@dataclass(frozen=True, slots=True)
class KeyRow:
    cmk_id: str
    description: str
    state: KeyState
    policy_json: str
    created_at: float
    deletion_date: float | None
    current_version: int


@dataclass(frozen=True, slots=True)
class AuditEntry:
    seq: int
    ts: float
    principal: str
    operation: str
    cmk_id: str | None
    outcome: str
    reason: str
    context: dict[str, str]
    entry_hash: str


def _entry_hash(prev: str, fields: dict[str, Any]) -> str:
    body = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(prev.encode() + b"|" + body).hexdigest()


class AccountStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def create_schema(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def dispose(self) -> None:
        await self._engine.dispose()

    # --- keys ----------------------------------------------------------------------

    async def insert_key(self, cmk_id: str, description: str, policy_json: str,
                         sealed_v1: bytes, now: float) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(keys.insert().values(
                cmk_id=cmk_id, description=description, state=KeyState.ENABLED,
                policy_json=policy_json, created_at=now, deletion_date=None))
            await conn.execute(key_versions.insert().values(
                cmk_id=cmk_id, version=1, sealed_material=sealed_v1, created_at=now))

    async def get_key(self, cmk_id: str) -> KeyRow | None:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(keys).where(keys.c.cmk_id == cmk_id))).first()
            if r is None:
                return None
            v = (await conn.execute(select(func.max(key_versions.c.version))
                                    .where(key_versions.c.cmk_id == cmk_id))).scalar()
        m = r._mapping
        return KeyRow(m["cmk_id"], m["description"], KeyState(m["state"]), m["policy_json"],
                      m["created_at"], m["deletion_date"], int(v or 0))

    async def get_version(self, cmk_id: str, version: int) -> bytes | None:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(key_versions.c.sealed_material).where(and_(
                key_versions.c.cmk_id == cmk_id, key_versions.c.version == version)))).first()
        return None if r is None else bytes(r[0])

    async def add_version(self, cmk_id: str, version: int, sealed: bytes,
                          now: float) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(key_versions.insert().values(
                cmk_id=cmk_id, version=version, sealed_material=sealed, created_at=now))

    async def set_state(self, cmk_id: str, state: KeyState,
                        deletion_date: float | None = None) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(update(keys).where(keys.c.cmk_id == cmk_id)
                               .values(state=state, deletion_date=deletion_date))

    async def set_policy(self, cmk_id: str, policy_json: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(update(keys).where(keys.c.cmk_id == cmk_id)
                               .values(policy_json=policy_json))

    async def destroy(self, cmk_id: str) -> None:
        """Crypto-shred: delete every version's material (secure_delete overwrites pages)."""
        async with self._engine.begin() as conn:
            await conn.execute(delete(key_versions).where(key_versions.c.cmk_id == cmk_id))
            await conn.execute(update(keys).where(keys.c.cmk_id == cmk_id)
                               .values(state=KeyState.DESTROYED))

    async def version_count(self, cmk_id: str) -> int:
        async with self._engine.begin() as conn:
            return int((await conn.execute(select(func.count()).select_from(key_versions)
                                           .where(key_versions.c.cmk_id == cmk_id)))
                       .scalar_one())

    # --- replay protection -------------------------------------------------------------

    async def use_nonce(self, principal: str, nonce: str, now: float,
                        expires_at: float) -> bool:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(delete(nonces).where(nonces.c.expires_at < now))
                await conn.execute(nonces.insert().values(
                    principal=principal, nonce=nonce, expires_at=expires_at))
            return True
        except IntegrityError:
            return False

    # --- audit ---------------------------------------------------------------------

    async def append_audit(self, *, ts: float, principal: str, operation: str,
                           cmk_id: str | None, outcome: str, reason: str,
                           context: dict[str, str]) -> None:
        ctx_json = json.dumps(context, sort_keys=True, separators=(",", ":"))
        async with self._engine.begin() as conn:
            prev = (await conn.execute(select(audit.c.entry_hash)
                                       .order_by(audit.c.seq.desc()).limit(1))).scalar()
            prev = prev or GENESIS
            fields = {"ts": ts, "principal": principal, "operation": operation,
                      "cmk_id": cmk_id, "outcome": outcome, "reason": reason,
                      "context_json": ctx_json}
            await conn.execute(audit.insert().values(
                **fields, prev_hash=prev, entry_hash=_entry_hash(prev, fields)))

    async def list_audit(self, since_seq: int, limit: int) -> list[AuditEntry]:
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(audit).where(audit.c.seq > since_seq)
                                       .order_by(audit.c.seq.asc()).limit(limit))).all()
        return [AuditEntry(m["seq"], m["ts"], m["principal"], m["operation"], m["cmk_id"],
                           m["outcome"], m["reason"], json.loads(m["context_json"]),
                           m["entry_hash"]) for m in (r._mapping for r in rows)]

    async def verify_audit(self) -> tuple[bool, int]:
        """Recompute the hash chain. Returns (intact, entries checked)."""
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(audit).order_by(audit.c.seq.asc()))).all()
        prev = GENESIS
        for r in rows:
            m = r._mapping
            fields = {k: m[k] for k in ("ts", "principal", "operation", "cmk_id", "outcome",
                                         "reason", "context_json")}
            if m["prev_hash"] != prev or m["entry_hash"] != _entry_hash(prev, fields):
                return False, len(rows)
            prev = m["entry_hash"]
        return True, len(rows)

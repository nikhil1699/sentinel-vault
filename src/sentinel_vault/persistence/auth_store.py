"""Persistence for tenants, users, sessions and login throttling (``auth.db``).

Session tokens are never stored: only SHA-256(token). A copy of this DB cannot be
replayed as live sessions.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    String,
    Table,
    and_,
    func,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel_vault.domain.ids import SessionId, TenantId, UserId

metadata = MetaData()

tenants = Table(
    "tenants", metadata,
    Column("tenant_id", String(32), primary_key=True),
    Column("frozen", Boolean, nullable=False, default=False),
    Column("created_at", Float, nullable=False),
)

users = Table(
    "users", metadata,
    Column("tenant_id", String(32), primary_key=True),
    Column("user_id", String(32), primary_key=True),
    Column("password_hash", String(256), nullable=False),
    Column("scopes", String(128), nullable=False),
    Column("disabled", Boolean, nullable=False, default=False),
    Column("created_at", Float, nullable=False),
    ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"]),
)

sessions = Table(
    "sessions", metadata,
    Column("session_hash", String(64), primary_key=True),
    Column("session_id", String(40), nullable=False, unique=True),
    Column("tenant_id", String(32), nullable=False, index=True),
    Column("user_id", String(32), nullable=False),
    Column("scopes", String(128), nullable=False),
    Column("created_at", Float, nullable=False),
    Column("last_seen", Float, nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("revoked_at", Float, nullable=True),
    Column("revoke_reason", String(32), nullable=True),
    ForeignKeyConstraint(["tenant_id", "user_id"], ["users.tenant_id", "users.user_id"]),
)

login_failures = Table(
    "login_failures", metadata,
    Column("key", String(128), primary_key=True),
    Column("count", Integer, nullable=False),
    Column("locked_until", Float, nullable=False),
    Column("last_failure", Float, nullable=True),
)


class DuplicateError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class UserRow:
    tenant_id: TenantId
    user_id: UserId
    password_hash: str
    scopes: str
    disabled: bool


@dataclass(frozen=True, slots=True)
class SessionRow:
    session_hash: str
    session_id: SessionId
    tenant_id: TenantId
    user_id: UserId
    scopes: str
    created_at: float
    last_seen: float
    expires_at: float
    revoked_at: float | None
    tenant_frozen: bool
    user_disabled: bool


def _session_row(r: object) -> SessionRow:
    m = r._mapping  # type: ignore[attr-defined]
    return SessionRow(
        session_hash=m["session_hash"], session_id=SessionId(m["session_id"]),
        tenant_id=TenantId(m["tenant_id"]), user_id=UserId(m["user_id"]),
        scopes=m["scopes"], created_at=m["created_at"], last_seen=m["last_seen"],
        expires_at=m["expires_at"], revoked_at=m["revoked_at"],
        tenant_frozen=bool(m["frozen"]), user_disabled=bool(m["disabled"]),
    )


class AuthStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def create_schema(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
            # In-place migration for databases created before last_failure existed.
            cols = {str(r._mapping["name"]) for r in (await conn.exec_driver_sql(
                "PRAGMA table_info(login_failures)")).all()}
            if "last_failure" not in cols:
                await conn.exec_driver_sql(
                    "ALTER TABLE login_failures ADD COLUMN last_failure FLOAT")

    # --- tenants -----------------------------------------------------------------

    async def create_tenant(self, tenant_id: TenantId, now: float) -> bool:
        """Returns False if it already existed."""
        try:
            async with self._engine.begin() as conn:
                await conn.execute(tenants.insert().values(
                    tenant_id=tenant_id, frozen=False, created_at=now))
            return True
        except IntegrityError:
            return False

    async def tenant_frozen(self, tenant_id: TenantId) -> bool | None:
        async with self._engine.begin() as conn:
            row = (await conn.execute(
                select(tenants.c.frozen).where(tenants.c.tenant_id == tenant_id))).first()
        return None if row is None else bool(row[0])

    async def set_frozen_and_revoke(self, tenant_id: TenantId, frozen: bool,
                                    now: float) -> int:
        """Freeze/unfreeze a tenant. Freezing revokes every session in the same transaction."""
        async with self._engine.begin() as conn:
            await conn.execute(update(tenants).where(tenants.c.tenant_id == tenant_id)
                               .values(frozen=frozen))
            if not frozen:
                return 0
            res = await conn.execute(
                update(sessions)
                .where(and_(sessions.c.tenant_id == tenant_id, sessions.c.revoked_at.is_(None)))
                .values(revoked_at=now, revoke_reason="tenant_frozen"))
            return int(res.rowcount)

    # --- users -------------------------------------------------------------------

    async def create_user(self, row: UserRow, now: float) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(users.insert().values(
                    tenant_id=row.tenant_id, user_id=row.user_id,
                    password_hash=row.password_hash, scopes=row.scopes,
                    disabled=row.disabled, created_at=now))
        except IntegrityError as exc:
            raise DuplicateError from exc

    async def get_user(self, tenant_id: TenantId, user_id: UserId) -> UserRow | None:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(users).where(and_(
                users.c.tenant_id == tenant_id, users.c.user_id == user_id)))).first()
        if r is None:
            return None
        m = r._mapping
        return UserRow(TenantId(m["tenant_id"]), UserId(m["user_id"]), m["password_hash"],
                       m["scopes"], bool(m["disabled"]))

    async def update_password_hash(self, tenant_id: TenantId, user_id: UserId,
                                   new_hash: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(update(users).where(and_(
                users.c.tenant_id == tenant_id, users.c.user_id == user_id))
                .values(password_hash=new_hash))

    async def set_user_disabled(self, tenant_id: TenantId, user_id: UserId,
                                disabled: bool, now: float) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(update(users).where(and_(
                users.c.tenant_id == tenant_id, users.c.user_id == user_id))
                .values(disabled=disabled))
            if disabled:
                await conn.execute(update(sessions).where(and_(
                    sessions.c.tenant_id == tenant_id, sessions.c.user_id == user_id,
                    sessions.c.revoked_at.is_(None)))
                    .values(revoked_at=now, revoke_reason="user_disabled"))

    # --- sessions ----------------------------------------------------------------

    def _live(self, now: float, idle_cutoff: float) -> object:
        return and_(sessions.c.revoked_at.is_(None), sessions.c.expires_at > now,
                    sessions.c.last_seen > idle_cutoff)

    async def create_session(self, *, session_hash: str, session_id: SessionId,
                             tenant_id: TenantId, user_id: UserId, scopes: str,
                             now: float, expires_at: float, idle_cutoff: float,
                             max_sessions: int) -> int:
        """Insert a session; revoke the oldest live ones beyond ``max_sessions``.

        One transaction (BEGIN IMMEDIATE), so concurrent logins can't exceed the cap.
        Returns how many sessions were evicted.
        """
        owner = and_(sessions.c.tenant_id == tenant_id, sessions.c.user_id == user_id)
        async with self._engine.begin() as conn:
            live = (await conn.execute(
                select(sessions.c.session_hash)
                .where(and_(owner, self._live(now, idle_cutoff)))  # type: ignore[arg-type]
                .order_by(sessions.c.created_at.asc(), sessions.c.session_id.asc())
            )).scalars().all()
            excess = len(live) - max_sessions + 1
            evict = list(live[:excess]) if excess > 0 else []
            if evict:
                await conn.execute(update(sessions)
                                   .where(sessions.c.session_hash.in_(evict))
                                   .values(revoked_at=now, revoke_reason="evicted"))
            await conn.execute(sessions.insert().values(
                session_hash=session_hash, session_id=session_id, tenant_id=tenant_id,
                user_id=user_id, scopes=scopes, created_at=now, last_seen=now,
                expires_at=expires_at, revoked_at=None, revoke_reason=None))
        return len(evict)

    async def get_session(self, session_hash: str) -> SessionRow | None:
        stmt = (
            select(sessions, tenants.c.frozen, users.c.disabled)
            .join(tenants, tenants.c.tenant_id == sessions.c.tenant_id)
            .join(users, and_(users.c.tenant_id == sessions.c.tenant_id,
                              users.c.user_id == sessions.c.user_id))
            .where(sessions.c.session_hash == session_hash)
        )
        async with self._engine.begin() as conn:
            r = (await conn.execute(stmt)).first()
        return None if r is None else _session_row(r)

    async def touch_session(self, session_hash: str, now: float) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(update(sessions)
                               .where(sessions.c.session_hash == session_hash)
                               .values(last_seen=now))

    async def revoke_session(self, tenant_id: TenantId, user_id: UserId,
                             session_id: SessionId, now: float, reason: str) -> bool:
        """Scoped by owner: a user can only ever revoke their own session."""
        async with self._engine.begin() as conn:
            res = await conn.execute(update(sessions).where(and_(
                sessions.c.tenant_id == tenant_id, sessions.c.user_id == user_id,
                sessions.c.session_id == session_id, sessions.c.revoked_at.is_(None)))
                .values(revoked_at=now, revoke_reason=reason))
        return int(res.rowcount) == 1

    async def revoke_user_sessions(self, tenant_id: TenantId, user_id: UserId,
                                   now: float, reason: str) -> int:
        async with self._engine.begin() as conn:
            res = await conn.execute(update(sessions).where(and_(
                sessions.c.tenant_id == tenant_id, sessions.c.user_id == user_id,
                sessions.c.revoked_at.is_(None)))
                .values(revoked_at=now, revoke_reason=reason))
        return int(res.rowcount)

    async def list_live_sessions(self, tenant_id: TenantId, user_id: UserId, now: float,
                                 idle_cutoff: float) -> list[SessionRow]:
        stmt = (
            select(sessions, tenants.c.frozen, users.c.disabled)
            .join(tenants, tenants.c.tenant_id == sessions.c.tenant_id)
            .join(users, and_(users.c.tenant_id == sessions.c.tenant_id,
                              users.c.user_id == sessions.c.user_id))
            .where(and_(sessions.c.tenant_id == tenant_id, sessions.c.user_id == user_id,
                        self._live(now, idle_cutoff)))  # type: ignore[arg-type]
            .order_by(sessions.c.created_at.asc())
        )
        async with self._engine.begin() as conn:
            return [_session_row(r) for r in (await conn.execute(stmt)).all()]

    async def count_live_sessions(self, tenant_id: TenantId, now: float,
                                  idle_cutoff: float) -> int:
        async with self._engine.begin() as conn:
            return int((await conn.execute(
                select(func.count()).select_from(sessions).where(and_(
                    sessions.c.tenant_id == tenant_id,
                    self._live(now, idle_cutoff)))  # type: ignore[arg-type]
            )).scalar_one())

    # --- login throttling -------------------------------------------------------------

    async def locked_until(self, key: str) -> float:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(login_failures.c.locked_until)
                                    .where(login_failures.c.key == key))).first()
        return 0.0 if r is None else float(r[0])

    async def record_failure(self, key: str, now: float, threshold: int, base: float,
                             cap: float, window: float = 900.0) -> int:
        """Count a failed login. The count restarts after ``window`` seconds without a
        failure, so old typos never add up to a permanent, ever-growing lockout."""
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(login_failures.c.count,
                                           login_failures.c.last_failure)
                                    .where(login_failures.c.key == key))).first()
            stale = r is None or now - float(r[1] or 0.0) > window
            count = 1 if stale else int(r[0]) + 1  # type: ignore[index]
            locked = 0.0
            if count >= threshold:
                locked = now + min(cap, base * (2 ** (count - threshold)))
            if r is None:
                await conn.execute(login_failures.insert().values(
                    key=key, count=count, locked_until=locked, last_failure=now))
            else:
                await conn.execute(update(login_failures).where(login_failures.c.key == key)
                                   .values(count=count, locked_until=locked, last_failure=now))
        return count

    async def clear_failures(self, key: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(login_failures.delete().where(login_failures.c.key == key))

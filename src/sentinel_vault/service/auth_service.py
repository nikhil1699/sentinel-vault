"""Authentication and session management (PLAN §17).

Server-side opaque sessions so revocation is instant. All failure paths raise the
same ``AuthenticationError`` so a caller can't tell "no such user" from "wrong
password" from "expired" from "revoked".
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import (
    Principal,
    Scope,
    SessionInfo,
    scopes_from_str,
    scopes_to_str,
    ts,
)
from sentinel_vault.domain.ids import SessionId, TenantId, UserId
from sentinel_vault.persistence.auth_store import AuthStore, DuplicateError, SessionRow, UserRow
from sentinel_vault.security.errors import (
    AuthenticationError,
    ConflictError,
    InvalidInputError,
    NotFoundError,
    RateLimitedError,
    TenantFrozenError,
)
from sentinel_vault.security.logging import get_logger
from sentinel_vault.security.sensitive import Sensitive

log = get_logger(__name__)

Clock = Callable[[], float]

TOKEN_PREFIX = "svs_"  # noqa: S105 - public prefix so secret scanners spot leaks
_TOKEN_RE = re.compile(r"svs_[A-Za-z0-9_-]{43}")
_TOUCH_INTERVAL_SECONDS = 15.0
_MAX_PASSWORD_LENGTH = 256


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class LoginResult:
    token: Sensitive[str]
    session: SessionInfo


class AuthService:
    def __init__(self, store: AuthStore, settings: Settings, clock: Clock = time.time) -> None:
        self._store = store
        self._s = settings
        self._clock = clock
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_kib,
            parallelism=settings.argon2_parallelism,
        )
        # Verified against when the user doesn't exist, so timing matches a real check.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))

    # --- provisioning ------------------------------------------------------------

    async def create_tenant(self, tenant_id: TenantId) -> bool:
        return await self._store.create_tenant(tenant_id, self._clock())

    async def create_user(self, tenant_id: TenantId, user_id: UserId,
                          password: Sensitive[str], scopes: Iterable[Scope]) -> None:
        pw = password.reveal()
        if not (self._s.password_min_length <= len(pw) <= _MAX_PASSWORD_LENGTH):
            raise InvalidInputError
        if await self._store.tenant_frozen(tenant_id) is None:
            raise NotFoundError
        pw_hash = await asyncio.to_thread(self._hasher.hash, pw)
        try:
            await self._store.create_user(
                UserRow(tenant_id, user_id, pw_hash, scopes_to_str(frozenset(scopes)), False),
                self._clock())
        except DuplicateError as exc:
            raise ConflictError from exc

    async def disable_user(self, tenant_id: TenantId, user_id: UserId) -> None:
        await self._store.set_user_disabled(tenant_id, user_id, True, self._clock())

    # --- login -------------------------------------------------------------------

    def _verify(self, pw_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(pw_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    async def login(self, tenant_id: TenantId, user_id: UserId, password: Sensitive[str],
                    client_ip: str) -> LoginResult:
        now = self._clock()
        user_key = f"user:{tenant_id}/{user_id}"
        ip_key = f"ip:{client_ip}"
        if max(await self._store.locked_until(user_key),
               await self._store.locked_until(ip_key)) > now:
            log.warning("login_throttled", tenant_id=tenant_id)
            raise RateLimitedError

        pw = password.reveal()
        user = await self._store.get_user(tenant_id, user_id)
        ok = await asyncio.to_thread(
            self._verify, user.password_hash if user else self._dummy_hash,
            pw if len(pw) <= _MAX_PASSWORD_LENGTH else "")
        if user is None or not ok or user.disabled:
            for key, limit in ((user_key, self._s.login_max_failures),
                               (ip_key, self._s.login_ip_max_failures)):
                await self._store.record_failure(
                    key, now, limit, self._s.login_lockout_base_seconds,
                    self._s.login_lockout_max_seconds, self._s.login_failure_window_seconds)
            log.info("login_failed", tenant_id=tenant_id)
            raise AuthenticationError

        frozen = await self._store.tenant_frozen(tenant_id)
        if frozen:
            raise TenantFrozenError
        await self._store.clear_failures(user_key)
        if self._hasher.check_needs_rehash(user.password_hash):
            new_hash = await asyncio.to_thread(self._hasher.hash, pw)
            await self._store.update_password_hash(tenant_id, user_id, new_hash)

        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        session_id = SessionId.new()
        expires = now + self._s.session_absolute_seconds
        evicted = await self._store.create_session(
            session_hash=hash_token(token), session_id=session_id, tenant_id=tenant_id,
            user_id=user_id, scopes=user.scopes, now=now, expires_at=expires,
            idle_cutoff=now - self._s.session_idle_seconds,
            max_sessions=self._s.max_sessions_per_user)
        log.info("login_ok", tenant_id=tenant_id, count=evicted)
        return LoginResult(
            token=Sensitive(token),
            session=SessionInfo(session_id=session_id, created_at=ts(now),
                                last_seen_at=ts(now), expires_at=ts(expires),
                                scopes=scopes_from_str(user.scopes), current=True))

    # --- per-request authentication -------------------------------------------------

    def _is_live(self, row: SessionRow, now: float) -> bool:
        return (row.revoked_at is None and not row.tenant_frozen and not row.user_disabled
                and now < row.expires_at
                and now - row.last_seen < self._s.session_idle_seconds)

    async def authenticate(self, token: str) -> Principal:
        if not _TOKEN_RE.fullmatch(token):
            raise AuthenticationError
        now = self._clock()
        h = hash_token(token)
        row = await self._store.get_session(h)
        if row is None or not self._is_live(row, now):
            raise AuthenticationError
        if now - row.last_seen >= _TOUCH_INTERVAL_SECONDS:
            await self._store.touch_session(h, now)
        return Principal(tenant_id=row.tenant_id, user_id=row.user_id,
                         session_id=row.session_id, scopes=scopes_from_str(row.scopes))

    # --- self-service session management ----------------------------------------------

    async def logout(self, p: Principal) -> None:
        await self._store.revoke_session(p.tenant_id, p.user_id, p.session_id,
                                         self._clock(), "logout")

    async def revoke_own_session(self, p: Principal, session_id: SessionId) -> None:
        if not await self._store.revoke_session(p.tenant_id, p.user_id, session_id,
                                                self._clock(), "logout"):
            raise NotFoundError

    async def logout_all(self, p: Principal) -> int:
        return await self._store.revoke_user_sessions(p.tenant_id, p.user_id,
                                                      self._clock(), "logout_all")

    async def list_sessions(self, p: Principal) -> list[SessionInfo]:
        now = self._clock()
        rows = await self._store.list_live_sessions(
            p.tenant_id, p.user_id, now, now - self._s.session_idle_seconds)
        return [SessionInfo(session_id=r.session_id, created_at=ts(r.created_at),
                            last_seen_at=ts(r.last_seen), expires_at=ts(r.expires_at),
                            scopes=scopes_from_str(r.scopes),
                            current=r.session_id == p.session_id) for r in rows]

    # --- containment hooks (used by M7) -------------------------------------------------

    async def freeze_tenant(self, tenant_id: TenantId) -> int:
        n = await self._store.set_frozen_and_revoke(tenant_id, True, self._clock())
        log.warning("tenant_frozen", tenant_id=tenant_id, count=n)
        return n

    async def unfreeze_tenant(self, tenant_id: TenantId) -> None:
        await self._store.set_frozen_and_revoke(tenant_id, False, self._clock())

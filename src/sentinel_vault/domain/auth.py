"""Auth domain types: scopes, principals, sessions."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from sentinel_vault.domain.ids import SessionId, TenantId, UserId


class Scope(StrEnum):
    INGEST = "ingest"
    QUERY = "query"
    REIDENTIFY = "reidentify"
    ADMIN = "admin"


def scopes_to_str(scopes: frozenset[Scope]) -> str:
    return ",".join(sorted(s.value for s in scopes))


def scopes_from_str(raw: str) -> frozenset[Scope]:
    return frozenset(Scope(s) for s in raw.split(",") if s)


class Principal(BaseModel):
    """Who is calling. Built only from a verified session row, never from request data."""

    model_config = ConfigDict(frozen=True)

    tenant_id: TenantId
    user_id: UserId
    session_id: SessionId
    scopes: frozenset[Scope]

    def has(self, scope: Scope) -> bool:
        return scope in self.scopes


class SessionInfo(BaseModel):
    """What a user may see about a session. Never includes the token or its hash."""

    model_config = ConfigDict(frozen=True)

    session_id: SessionId
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    scopes: frozenset[Scope]
    current: bool = False


def ts(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=UTC)

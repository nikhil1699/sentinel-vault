"""Login, logout and session management endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints

from sentinel_vault.api.deps import CurrentPrincipal, auth_service
from sentinel_vault.domain.auth import Scope, SessionInfo
from sentinel_vault.domain.ids import SessionId, TenantId, UserId
from sentinel_vault.security.sensitive import Sensitive
from sentinel_vault.service.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])

Password = Sensitive[Annotated[str, StringConstraints(min_length=1, max_length=256)]]
Svc = Annotated[AuthService, Depends(auth_service)]


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    username: UserId
    password: Password


class LoginResponse(BaseModel):
    token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - token type, not a secret
    session_id: SessionId
    expires_at: datetime
    idle_timeout_seconds: int
    scopes: frozenset[Scope]


class Me(BaseModel):
    tenant_id: TenantId
    user_id: UserId
    session_id: SessionId
    scopes: frozenset[Scope]


class RevokedCount(BaseModel):
    revoked: int


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, svc: Svc) -> LoginResponse:
    client_ip = request.client.host if request.client else "unknown"
    result = await svc.login(body.tenant_id, body.username, body.password, client_ip)
    s = request.app.state.settings
    return LoginResponse(
        token=result.token.reveal(),  # the one place a token leaves the service
        session_id=result.session.session_id,
        expires_at=result.session.expires_at,
        idle_timeout_seconds=s.session_idle_seconds,
        scopes=result.session.scopes,
    )


@router.get("/me", response_model=Me)
async def me(principal: CurrentPrincipal) -> Me:
    return Me(**principal.model_dump())


@router.post("/logout", status_code=204)
async def logout(principal: CurrentPrincipal, svc: Svc) -> Response:
    await svc.logout(principal)
    return Response(status_code=204)


@router.post("/logout-all", response_model=RevokedCount)
async def logout_all(principal: CurrentPrincipal, svc: Svc) -> RevokedCount:
    return RevokedCount(revoked=await svc.logout_all(principal))


@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(principal: CurrentPrincipal, svc: Svc) -> list[SessionInfo]:
    return await svc.list_sessions(principal)


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(session_id: SessionId, principal: CurrentPrincipal,
                         svc: Svc) -> Response:
    await svc.revoke_own_session(principal, session_id)
    return Response(status_code=204)

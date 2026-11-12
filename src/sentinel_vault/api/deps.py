"""FastAPI dependencies: the authorization boundary.

Every protected route depends on ``get_principal``. The tenant a request acts for comes
only from the verified session, never from a path, query, header or body field.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sentinel_vault.domain.auth import Principal, Scope
from sentinel_vault.security.errors import AuthenticationError, PermissionDeniedError
from sentinel_vault.service.auth_service import AuthService

_bearer = HTTPBearer(auto_error=False)


def auth_service(request: Request) -> AuthService:
    svc = request.app.state.auth_service
    assert isinstance(svc, AuthService)  # noqa: S101 - wiring invariant
    return svc


async def get_principal(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise AuthenticationError
    return await auth_service(request).authenticate(creds.credentials)


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_scope(scope: Scope) -> Callable[[Principal], Awaitable[Principal]]:
    async def _dep(principal: CurrentPrincipal) -> Principal:
        if not principal.has(scope):
            raise PermissionDeniedError
        return principal

    return _dep

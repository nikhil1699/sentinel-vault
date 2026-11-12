"""Error types with fixed public messages, and FastAPI handlers that never echo input.

Rule: a client sees only ``{code, message, request_id}``. ``message`` is a constant
chosen by us, never built from exception text or request data. Details go to logs,
which are redacted.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinel_vault.security.logging import get_logger

log = get_logger(__name__)

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class AppError(Exception):
    status_code: ClassVar[int] = 500
    code: ClassVar[str] = "internal_error"
    public_message: ClassVar[str] = "Internal error."


class AuthenticationError(AppError):
    status_code = 401
    code = "unauthenticated"
    public_message = "Invalid or expired credentials."


class PermissionDeniedError(AppError):
    status_code = 403
    code = "forbidden"
    public_message = "Not allowed."


class NotFoundError(AppError):
    """Also used for cross-tenant access, so existence is never confirmed."""

    status_code = 404
    code = "not_found"
    public_message = "Not found."


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    public_message = "Conflict."


class TenantFrozenError(AppError):
    status_code = 423
    code = "tenant_frozen"
    public_message = "Tenant is temporarily locked."


class PolicyViolationError(AppError):
    status_code = 422
    code = "policy_violation"
    public_message = "Request blocked by data protection policy."


class DependencyUnavailableError(AppError):
    """KMS or another dependency failed. We fail closed."""

    status_code = 503
    code = "dependency_unavailable"
    public_message = "A required dependency is unavailable."


_HTTP_MESSAGES: dict[int, tuple[str, str]] = {
    400: ("bad_request", "Bad request."),
    401: ("unauthenticated", "Invalid or expired credentials."),
    403: ("forbidden", "Not allowed."),
    404: ("not_found", "Not found."),
    405: ("method_not_allowed", "Method not allowed."),
    413: ("payload_too_large", "Payload too large."),
    415: ("unsupported_media_type", "Unsupported media type."),
    429: ("rate_limited", "Too many requests."),
}


def request_id_of(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    return rid if isinstance(rid, str) else "unknown"


def error_response(request: Request, status: int, code: str, message: str,
                   extra: dict[str, Any] | None = None) -> JSONResponse:
    rid = request_id_of(request)
    body: dict[str, Any] = {"code": code, "message": message, "request_id": rid}
    if extra:
        body.update(extra)
    return JSONResponse(
        {"error": body},
        status_code=status,
        headers={"x-request-id": rid, "cache-control": "no-store"},
    )


def _safe_loc(loc: tuple[Any, ...]) -> list[str | int]:
    """Keep int indexes and identifier-shaped names; hide anything else (may be PHI)."""
    out: list[str | int] = []
    for part in loc:
        if isinstance(part, int):
            out.append(part)
        elif isinstance(part, str) and _IDENTIFIER.match(part):
            out.append(part)
        else:
            out.append("<field>")
    return out


async def _app_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AppError):
        return await _unhandled(request, exc)
    log.warning("app_error", error_code=exc.code, error_type=type(exc).__name__,
                status=exc.status_code)
    return error_response(request, exc.status_code, exc.code, exc.public_message)


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):
        return await _unhandled(request, exc)
    fields = [{"loc": _safe_loc(tuple(e.get("loc", ()))), "type": str(e.get("type", ""))}
              for e in exc.errors()]
    log.info("validation_error", count=len(fields))
    return error_response(request, 422, "validation_error", "Request validation failed.",
                          {"fields": fields})


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):
        return await _unhandled(request, exc)
    code, message = _HTTP_MESSAGES.get(exc.status_code, ("http_error", "Request failed."))
    return error_response(request, exc.status_code, code, message)


async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled_exception", error_type=type(exc).__name__, exc_info=exc)
    return error_response(request, 500, "internal_error", "Internal error.")


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unhandled)

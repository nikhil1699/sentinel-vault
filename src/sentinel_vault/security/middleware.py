"""Request context middleware (pure ASGI, fully async).

- Assigns a request id. An inbound ``x-request-id`` is accepted only if it is a UUID,
  so clients can't inject text into our logs.
- Adds no-store and nosniff headers to every response.
- Logs one access line with the *route template*, never the raw path or query string.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel_vault.security.logging import get_logger

log = get_logger("access")

_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
)


def _inbound_request_id(scope: Scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name == b"x-request-id":
            try:
                return str(uuid.UUID(value.decode("ascii")))
            except (ValueError, UnicodeDecodeError):
                return None
    return None


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        rid = _inbound_request_id(scope) or str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = rid
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid)

        status = 500
        start = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers: list[Any] = list(message.get("headers", []))
                present = {h[0].lower() for h in headers}
                if b"x-request-id" not in present:
                    headers.append((b"x-request-id", rid.encode()))
                headers.extend(h for h in _SECURITY_HEADERS if h[0] not in present)
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            log.info(
                "request",
                method=scope.get("method"),
                route=getattr(route, "path", "unmatched"),
                status=status,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
            )

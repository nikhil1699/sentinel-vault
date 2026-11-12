"""Shared FastAPI app skeleton: logging, error handlers, middleware, health.

Every service (Sentinel API, Customer KMS, mock LLM) is built from this, so each one
gets the same leakage protections. Sharing this code does not share trust: each
service still runs as its own process with its own data and keys.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI
from pydantic import BaseModel

from sentinel_vault.security.errors import install_error_handlers
from sentinel_vault.security.logging import configure_logging
from sentinel_vault.security.middleware import RequestContextMiddleware


class Health(BaseModel):
    status: str
    service: str


def build_app(service: str, title: str, log_level: str = "INFO",
              configure_logs: bool = True) -> FastAPI:
    if configure_logs:
        configure_logging(log_level)
    app = FastAPI(title=title, redoc_url=None)
    install_error_handlers(app)
    app.add_middleware(RequestContextMiddleware)

    router = APIRouter(tags=["health"])

    @router.get("/health", response_model=Health)
    async def health() -> Health:
        return Health(status="ok", service=service)

    app.include_router(router)
    return app

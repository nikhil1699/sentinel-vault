"""Sentinel API app factory. Run: ``uvicorn --factory sentinel_vault.api.app:create_app``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinel_vault.api.routes import auth as auth_routes
from sentinel_vault.config import Settings
from sentinel_vault.persistence.auth_store import AuthStore
from sentinel_vault.persistence.sqlite import create_sqlite_engine
from sentinel_vault.security.http import build_app
from sentinel_vault.service.auth_service import AuthService


def create_app(settings: Settings | None = None, configure_logs: bool = True,
               clock: Callable[[], float] | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_sqlite_engine(settings.auth_db_path)
        store = AuthStore(engine)
        await store.create_schema()
        app.state.auth_service = (AuthService(store, settings, clock) if clock
                                  else AuthService(store, settings))
        try:
            yield
        finally:
            await engine.dispose()

    app = build_app("sentinel-api", "Sentinel Vault API", settings.log_level, configure_logs,
                    lifespan=lifespan)
    app.state.settings = settings
    app.include_router(auth_routes.router)
    return app

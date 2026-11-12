"""Sentinel API app factory. Run: ``uvicorn --factory sentinel_vault.api.app:create_app``."""

from __future__ import annotations

from fastapi import FastAPI

from sentinel_vault.config import Settings
from sentinel_vault.security.http import build_app


def create_app(settings: Settings | None = None, configure_logs: bool = True) -> FastAPI:
    settings = settings or Settings()
    app = build_app("sentinel-api", "Sentinel Vault API", settings.log_level, configure_logs)
    app.state.settings = settings
    return app

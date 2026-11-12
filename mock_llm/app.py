"""Mock external LLM. Records what it receives so tests can prove no PII arrived (M6)."""

from __future__ import annotations

from fastapi import FastAPI

from sentinel_vault.security.http import build_app


def create_app(configure_logs: bool = True) -> FastAPI:
    return build_app("mock-llm", "Mock LLM (external system)", configure_logs=configure_logs)

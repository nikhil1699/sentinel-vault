"""Sentinel API app factory. Run: ``uvicorn --factory sentinel_vault.api.app:create_app``."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from sentinel_vault.api.routes import auth as auth_routes
from sentinel_vault.api.routes import documents as doc_routes
from sentinel_vault.api.routes import query as query_routes
from sentinel_vault.config import Settings
from sentinel_vault.crypto.dek_cache import DekCache
from sentinel_vault.kms_client.provider import SignedKmsProvider
from sentinel_vault.persistence.auth_store import AuthStore
from sentinel_vault.persistence.keyring_store import KeyringStore
from sentinel_vault.persistence.sqlite import create_sqlite_engine
from sentinel_vault.persistence.vault_store import VaultStore
from sentinel_vault.persistence.vector_store import VectorStore
from sentinel_vault.privacy.detector import PiiDetector, build_presidio_analyzer
from sentinel_vault.privacy.egress import EgressGuard, LlmClient
from sentinel_vault.retrieval.embedder import Embedder, build_embedder
from sentinel_vault.security.files import check_private
from sentinel_vault.security.http import build_app
from sentinel_vault.service.auth_service import AuthService
from sentinel_vault.service.ingest import IngestService, PolicyService
from sentinel_vault.service.keyring import Keyring
from sentinel_vault.service.query import QueryService
from sentinel_vault.service.rotation import RotationService
from sentinel_vault.service.tokenization import Tokenizer


def _load_service_key(settings: Settings) -> Ed25519PrivateKey:
    path = settings.service_private_key_path
    check_private(path)
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("service key must be Ed25519")
    return key


def create_app(settings: Settings | None = None, configure_logs: bool = True,
               clock: Callable[[], float] | None = None,
               kms_http: httpx.AsyncClient | None = None,
               service_key: Ed25519PrivateKey | None = None,
               detector: PiiDetector | None = None,
               embedder: Embedder | None = None,
               llm_http: httpx.AsyncClient | None = None,
               resume_jobs: bool = True) -> FastAPI:
    """All collaborators are injectable so tests can wire the real KMS app in-process."""
    settings = settings or Settings()
    now = clock or time.time

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engines = [create_sqlite_engine(p) for p in (
            settings.auth_db_path, settings.keyring_db_path, settings.vector_db_path,
            settings.vault_db_path)]
        auth_store, kr_store = AuthStore(engines[0]), KeyringStore(engines[1])
        vec_store, vault_store = VectorStore(engines[2]), VaultStore(engines[3])
        for s in (auth_store, kr_store, vec_store, vault_store):
            await s.create_schema()

        own_http = kms_http is None
        http = kms_http or httpx.AsyncClient(base_url=settings.kms_url,
                                             timeout=settings.kms_timeout_seconds)
        provider = SignedKmsProvider(http, settings.service_principal,
                                     service_key or _load_service_key(settings),
                                     settings.kms_max_retries, clock)
        cache = (DekCache(settings.dek_cache_ttl_seconds, settings.dek_cache_max_uses,
                          clock=clock) if clock else
                 DekCache(settings.dek_cache_ttl_seconds, settings.dek_cache_max_uses))
        keyring = Keyring(kr_store, provider, cache, settings, now)
        policies = PolicyService(kr_store, now)
        tokenizer = Tokenizer(keyring, vault_store, now)
        det = detector or PiiDetector(build_presidio_analyzer(), settings.pii_score_threshold)
        emb = embedder or build_embedder(settings.embedder)
        own_llm = llm_http is None
        lhttp = llm_http or httpx.AsyncClient(base_url=settings.llm_url,
                                              timeout=settings.llm_timeout_seconds)
        auth = AuthService(auth_store, settings, now)

        app.state.auth_service = auth
        app.state.keyring = keyring
        app.state.policy_service = policies
        app.state.tokenizer = tokenizer
        app.state.ingest_service = IngestService(
            settings, keyring, tokenizer, det, emb, vec_store, policies, now)
        app.state.query_service = QueryService(
            settings, keyring, tokenizer, det, emb, vec_store, EgressGuard(det, tokenizer),
            LlmClient(lhttp, settings.llm_max_answer_chars))
        rotation = RotationService(settings, keyring, tokenizer, vec_store, vault_store, emb,
                                   auth, now)
        app.state.rotation_service = rotation
        if resume_jobs:
            await rotation.resume_pending()
        try:
            yield
        finally:
            await rotation.shutdown()
            if own_llm:
                await lhttp.aclose()
            cache.flush()
            if own_http:
                await http.aclose()
            for e in engines:
                await e.dispose()

    app = build_app("sentinel-api", "Sentinel Vault API", settings.log_level, configure_logs,
                    lifespan=lifespan)
    app.state.settings = settings
    app.include_router(auth_routes.router)
    app.include_router(doc_routes.router)
    app.include_router(query_routes.router)
    return app

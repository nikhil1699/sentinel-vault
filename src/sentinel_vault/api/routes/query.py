"""Process (agent query) and key-management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from sentinel_vault.api.deps import require_scope
from sentinel_vault.domain.auth import Principal, Scope
from sentinel_vault.domain.ids import ChunkId, DocumentId
from sentinel_vault.service.keyring import Keyring
from sentinel_vault.service.query import QueryRequest, QueryService
from sentinel_vault.service.rotation import RotationService

router = APIRouter(tags=["query"])

Admin = Annotated[Principal, Depends(require_scope(Scope.ADMIN))]
Query = Annotated[Principal, Depends(require_scope(Scope.QUERY))]


def _query(request: Request) -> QueryService:
    svc: QueryService = request.app.state.query_service
    return svc


def _rotation(request: Request) -> RotationService:
    svc: RotationService = request.app.state.rotation_service
    return svc


def _keyring(request: Request) -> Keyring:
    kr: Keyring = request.app.state.keyring
    return kr


class SourceOut(BaseModel):
    doc_id: DocumentId
    chunk_id: ChunkId
    score: float


class QueryResponse(BaseModel):
    answer: str
    sources: list[SourceOut]
    reidentified: bool
    egress_masked: int
    egress_blobs_removed: int


class JobRef(BaseModel):
    job_id: str


class JobOut(BaseModel):
    job_id: str
    kind: str
    state: str
    step: str
    processed: int


class Flushed(BaseModel):
    evicted: int


@router.post("/query", response_model=QueryResponse)
async def query(body: QueryRequest, p: Query,
                svc: Annotated[QueryService, Depends(_query)]) -> QueryResponse:
    r = await svc.query(p, body)
    return QueryResponse(
        answer=r.answer,
        sources=[SourceOut(doc_id=s.doc_id, chunk_id=s.chunk_id, score=s.score)
                 for s in r.sources],
        reidentified=r.reidentified, egress_masked=r.egress_masked,
        egress_blobs_removed=r.egress_blobs_removed)


@router.post("/tenant/keys/rewrap", response_model=JobRef, status_code=202)
async def rewrap(p: Admin, svc: Annotated[RotationService, Depends(_rotation)]) -> JobRef:
    """Call after rotating your CMK: re-wraps every DEK to the new version, no downtime."""
    return JobRef(job_id=await svc.start_rewrap(p.tenant_id))


@router.post("/tenant/contain", response_model=JobRef, status_code=202)
async def contain(p: Admin, svc: Annotated[RotationService, Depends(_rotation)]) -> JobRef:
    """Suspected key compromise: freeze, re-key and re-encrypt this tenant.

    All of the tenant's sessions (including this one) are revoked. Log in again after
    the job finishes to check its status.
    """
    return JobRef(job_id=await svc.start_containment(p.tenant_id))


@router.get("/tenant/jobs/{job_id}", response_model=JobOut)
async def job_status(job_id: str, p: Admin,
                     svc: Annotated[RotationService, Depends(_rotation)]) -> JobOut:
    j = await svc.get_job(p.tenant_id, job_id)
    return JobOut(job_id=j.job_id, kind=j.kind, state=j.state, step=j.step,
                  processed=j.processed)


@router.post("/tenant/cache/flush", response_model=Flushed)
async def flush(p: Admin, kr: Annotated[Keyring, Depends(_keyring)]) -> Flushed:
    """Drop our cached plaintext keys now (e.g. right after you revoke your CMK)."""
    return Flushed(evicted=kr.flush_tenant(p.tenant_id))

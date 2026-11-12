"""Tenant onboarding, data policy, Store and Retrieve endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, StringConstraints

from sentinel_vault.api.deps import require_scope
from sentinel_vault.domain.auth import Principal, Scope
from sentinel_vault.domain.ids import DocumentId, WorkspaceId
from sentinel_vault.privacy.policy import DataPolicy
from sentinel_vault.security.errors import PermissionDeniedError
from sentinel_vault.service.ingest import IngestRequest, IngestService, PolicyService, View
from sentinel_vault.service.keyring import Keyring

router = APIRouter(tags=["documents"])

Admin = Annotated[Principal, Depends(require_scope(Scope.ADMIN))]
Ingest = Annotated[Principal, Depends(require_scope(Scope.INGEST))]
Query = Annotated[Principal, Depends(require_scope(Scope.QUERY))]


def _ingest(request: Request) -> IngestService:
    svc: IngestService = request.app.state.ingest_service
    return svc


def _keyring(request: Request) -> Keyring:
    kr: Keyring = request.app.state.keyring
    return kr


def _policies(request: Request) -> PolicyService:
    ps: PolicyService = request.app.state.policy_service
    return ps


class KmsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kms_account: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,62}$")]
    cmk_id: Annotated[str, StringConstraints(pattern=r"^cmk_[0-9a-f]{32}$")]


class Ok(BaseModel):
    ok: bool = True


class IngestResponse(BaseModel):
    doc_id: DocumentId
    workspace_id: WorkspaceId
    chunks: int
    tokenized_entities: dict[str, int]
    dropped_fields: int


@router.put("/tenant/kms", response_model=Ok)
async def set_tenant_kms(body: KmsConfig, p: Admin,
                         kr: Annotated[Keyring, Depends(_keyring)]) -> Ok:
    """BYOK onboarding: the tenant admin registers their CMK. We probe it before accepting."""
    await kr.onboard(p.tenant_id, body.kms_account, body.cmk_id)
    return Ok()


@router.get("/tenant/policy", response_model=DataPolicy)
async def get_policy(p: Admin,
                     ps: Annotated[PolicyService, Depends(_policies)]) -> DataPolicy:
    return await ps.get(p.tenant_id)


@router.put("/tenant/policy", response_model=Ok)
async def set_policy(body: DataPolicy, p: Admin,
                     ps: Annotated[PolicyService, Depends(_policies)]) -> Ok:
    await ps.set(p.tenant_id, body)
    return Ok()


@router.post("/documents", response_model=IngestResponse, status_code=201)
async def ingest(body: IngestRequest, p: Ingest,
                 svc: Annotated[IngestService, Depends(_ingest)]) -> IngestResponse:
    r = await svc.ingest(p, body)
    return IngestResponse(doc_id=r.doc_id, workspace_id=r.workspace_id, chunks=r.chunks,
                          tokenized_entities=r.tokenized_entities,
                          dropped_fields=r.dropped_fields)


@router.get("/documents/{doc_id}")
async def get_document(doc_id: DocumentId, p: Query,
                       svc: Annotated[IngestService, Depends(_ingest)],
                       view: View = View.TOKENIZED) -> dict[str, Any]:
    """Tokenized view needs ``query``. Original (raw PII) also needs ``reidentify``."""
    if view == View.ORIGINAL and not p.has(Scope.REIDENTIFY):
        raise PermissionDeniedError
    return await svc.get_document(p, doc_id, view)

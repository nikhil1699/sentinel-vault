"""Customer KMS HTTP API (separate trust domain). ``POST /v1/<Operation>``.

Every route reads the raw body first, verifies the signature over those exact bytes,
then parses. Nothing is parsed or acted on before the caller is authenticated.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, FastAPI, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from customer_kms.config import KmsSettings
from customer_kms.errors import KmsInvalidRequestError
from customer_kms.policy import KeyPolicy
from customer_kms.protocol import b64d, b64e
from customer_kms.service import Caller, KmsService
from customer_kms.store import KeyState
from sentinel_vault.domain.auth import ts
from sentinel_vault.security.http import build_app

__all__ = ["KmsSettings", "create_app"]

CmkId = Annotated[str, StringConstraints(pattern=r"^cmk_[0-9a-f]{32}$")]
Blob = Annotated[str, StringConstraints(min_length=8, max_length=512)]


class _Req(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateKeyReq(_Req):
    description: Annotated[str, StringConstraints(max_length=256)] = ""


class KeyIdReq(_Req):
    cmk_id: CmkId


class PutPolicyReq(_Req):
    cmk_id: CmkId
    policy: KeyPolicy


class ScheduleDeletionReq(_Req):
    cmk_id: CmkId
    pending_days: int = 30


class GenerateDataKeyReq(_Req):
    cmk_id: CmkId
    encryption_context: dict[str, str] = Field(default_factory=dict)


class DecryptReq(_Req):
    ciphertext_blob: Blob
    encryption_context: dict[str, str] = Field(default_factory=dict)


class ListAuditReq(_Req):
    since_seq: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=1000)


class CreateKeyResp(BaseModel):
    cmk_id: str


class DataKeyResp(BaseModel):
    plaintext: str
    ciphertext_blob: str
    cmk_id: str
    cmk_version: int


class DecryptResp(BaseModel):
    plaintext: str
    cmk_id: str
    cmk_version: int


class ReEncryptResp(BaseModel):
    ciphertext_blob: str
    cmk_version: int


class VersionResp(BaseModel):
    cmk_version: int


class DescribeResp(BaseModel):
    cmk_id: str
    description: str
    state: KeyState
    current_version: int
    created_at: datetime
    deletion_date: datetime | None


class DeletionResp(BaseModel):
    deletion_date: datetime


class AuditItem(BaseModel):
    seq: int
    ts: datetime
    principal: str
    operation: str
    cmk_id: str | None
    outcome: str
    reason: str
    encryption_context: dict[str, str]
    entry_hash: str


class AuditResp(BaseModel):
    entries: list[AuditItem]


class VerifyAuditResp(BaseModel):
    intact: bool
    entries: int


class Ok(BaseModel):
    ok: bool = True


def _svc(request: Request) -> KmsService:
    svc = request.app.state.kms
    assert isinstance(svc, KmsService)  # noqa: S101 - wiring invariant
    return svc


async def _call[M: BaseModel](request: Request,
                               model: type[M]) -> tuple[KmsService, Caller, M]:
    svc = _svc(request)
    body = await request.body()
    if len(body) > request.app.state.settings.max_body_bytes:
        raise KmsInvalidRequestError
    caller = await svc.authenticate(request.method, request.url.path,
                                    {k.lower(): v for k, v in request.headers.items()}, body)
    try:
        return svc, caller, model.model_validate_json(body or b"{}")
    except ValidationError as exc:
        raise KmsInvalidRequestError from exc


def _blob(s: str) -> bytes:
    try:
        return b64d(s)
    except ValueError as exc:
        raise KmsInvalidRequestError from exc


router = APIRouter(prefix="/v1", tags=["kms"])


@router.post("/CreateKey", response_model=CreateKeyResp)
async def create_key(request: Request) -> CreateKeyResp:
    svc, c, req = await _call(request, CreateKeyReq)
    return CreateKeyResp(cmk_id=await svc.create_key(c, req.description))


@router.post("/PutKeyPolicy", response_model=Ok)
async def put_key_policy(request: Request) -> Ok:
    svc, c, req = await _call(request, PutPolicyReq)
    await svc.put_key_policy(c, req.cmk_id, req.policy)
    return Ok()


@router.post("/GetKeyPolicy", response_model=KeyPolicy)
async def get_key_policy(request: Request) -> KeyPolicy:
    svc, c, req = await _call(request, KeyIdReq)
    return await svc.get_key_policy(c, req.cmk_id)


@router.post("/DescribeKey", response_model=DescribeResp)
async def describe_key(request: Request) -> DescribeResp:
    svc, c, req = await _call(request, KeyIdReq)
    k = await svc.describe_key(c, req.cmk_id)
    return DescribeResp(cmk_id=k.cmk_id, description=k.description, state=k.state,
                        current_version=k.current_version, created_at=ts(k.created_at),
                        deletion_date=ts(k.deletion_date) if k.deletion_date else None)


@router.post("/RotateKey", response_model=VersionResp)
async def rotate_key(request: Request) -> VersionResp:
    svc, c, req = await _call(request, KeyIdReq)
    return VersionResp(cmk_version=await svc.rotate_key(c, req.cmk_id))


def _state_route(name: str, fn: Callable[[KmsService], Callable[..., object]]) -> None:
    async def handler(request: Request) -> Ok:
        svc, c, req = await _call(request, KeyIdReq)
        await fn(svc)(c, req.cmk_id)  # type: ignore[misc]
        return Ok()

    router.add_api_route(f"/{name}", handler, methods=["POST"], response_model=Ok, name=name)


_state_route("DisableKey", lambda s: s.disable_key)
_state_route("EnableKey", lambda s: s.enable_key)
_state_route("CancelKeyDeletion", lambda s: s.cancel_key_deletion)


@router.post("/ScheduleKeyDeletion", response_model=DeletionResp)
async def schedule_key_deletion(request: Request) -> DeletionResp:
    svc, c, req = await _call(request, ScheduleDeletionReq)
    return DeletionResp(deletion_date=ts(
        await svc.schedule_key_deletion(c, req.cmk_id, req.pending_days)))


@router.post("/GenerateDataKey", response_model=DataKeyResp)
async def generate_data_key(request: Request) -> DataKeyResp:
    svc, c, req = await _call(request, GenerateDataKeyReq)
    dk = await svc.generate_data_key(c, req.cmk_id, req.encryption_context)
    return DataKeyResp(plaintext=b64e(dk.plaintext), ciphertext_blob=b64e(dk.ciphertext_blob),
                       cmk_id=dk.cmk_id, cmk_version=dk.cmk_version)


@router.post("/Decrypt", response_model=DecryptResp)
async def decrypt(request: Request) -> DecryptResp:
    svc, c, req = await _call(request, DecryptReq)
    pt, cmk_id, v = await svc.decrypt(c, _blob(req.ciphertext_blob), req.encryption_context)
    return DecryptResp(plaintext=b64e(pt), cmk_id=cmk_id, cmk_version=v)


@router.post("/ReEncrypt", response_model=ReEncryptResp)
async def re_encrypt(request: Request) -> ReEncryptResp:
    svc, c, req = await _call(request, DecryptReq)
    blob, v = await svc.re_encrypt(c, _blob(req.ciphertext_blob), req.encryption_context)
    return ReEncryptResp(ciphertext_blob=b64e(blob), cmk_version=v)


@router.post("/ListAudit", response_model=AuditResp)
async def list_audit(request: Request) -> AuditResp:
    svc, c, req = await _call(request, ListAuditReq)
    entries = await svc.list_audit(c, req.since_seq, req.limit)
    return AuditResp(entries=[AuditItem(
        seq=e.seq, ts=ts(e.ts), principal=e.principal, operation=e.operation,
        cmk_id=e.cmk_id, outcome=e.outcome, reason=e.reason, encryption_context=e.context,
        entry_hash=e.entry_hash) for e in entries])


@router.post("/VerifyAudit", response_model=VerifyAuditResp)
async def verify_audit(request: Request) -> VerifyAuditResp:
    svc, c, _ = await _call(request, _Req)
    intact, n = await svc.verify_audit(c)
    return VerifyAuditResp(intact=intact, entries=n)


def create_app(settings: KmsSettings | None = None, configure_logs: bool = True,
               clock: Callable[[], float] | None = None) -> FastAPI:
    settings = settings or KmsSettings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        svc = KmsService(settings.data_dir, clock) if clock else KmsService(settings.data_dir)
        app.state.kms = svc
        try:
            yield
        finally:
            await svc.close()

    app = build_app("customer-kms", "Customer KMS (simulated)", settings.log_level,
                    configure_logs, lifespan=lifespan)
    app.state.settings = settings
    app.include_router(router)
    return app

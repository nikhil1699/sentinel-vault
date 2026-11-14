"""Store / Retrieve (PLAN §5): ingest a record, keep the original encrypted, and build a
tokenized, embedded, encrypted chunk set for retrieval.

Write path::

    record -> policy per field -> detect PII (normalized) -> tokens (tenant HMAC key)
      -> vault (encrypted originals) -> original + tokenized doc (encrypted, DOCUMENT DEK)
      -> chunk tokenized text -> embed -> encrypt chunks (VECTOR DEK) -> one transaction

Raw PII exists only in: the request, the encrypted original document, the encrypted vault.
It never reaches chunks, embeddings or logs.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import Principal
from sentinel_vault.domain.ids import ChunkId, DocumentId, TenantId, WorkspaceId
from sentinel_vault.persistence.keyring_store import KeyringStore, Purpose
from sentinel_vault.persistence.vector_store import ChunkRow, DocumentRow, VectorStore
from sentinel_vault.privacy.detector import PiiDetector, Span, prefer_known
from sentinel_vault.privacy.policy import DataPolicy, FieldAction
from sentinel_vault.retrieval.chunking import chunk_text, encode_chunk
from sentinel_vault.retrieval.embedder import Embedder
from sentinel_vault.security.errors import InvalidInputError, NotFoundError
from sentinel_vault.security.logging import get_logger
from sentinel_vault.service.keyring import Keyring, TenantNotOnboardedError
from sentinel_vault.service.tokenization import Tokenizer

log = get_logger(__name__)

Scalar = str | int | float | bool | None


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_id: WorkspaceId = WorkspaceId("default")
    fields: dict[str, Scalar] = Field(default_factory=dict)
    text: str | None = None


class View(StrEnum):
    TOKENIZED = "tokenized"
    ORIGINAL = "original"


@dataclass(frozen=True, slots=True)
class IngestResult:
    doc_id: DocumentId
    workspace_id: WorkspaceId
    chunks: int
    tokenized_entities: dict[str, int]
    dropped_fields: int


class PolicyService:
    def __init__(self, store: KeyringStore, clock: Callable[[], float] = time.time) -> None:
        self._store = store
        self._clock = clock

    async def get(self, tenant_id: TenantId) -> DataPolicy:
        raw = await self._store.get_policy(tenant_id)
        return DataPolicy() if raw is None else DataPolicy.model_validate_json(raw)

    async def set(self, tenant_id: TenantId, policy: DataPolicy) -> None:
        await self._store.set_policy(tenant_id, policy.model_dump_json(), self._clock())


def known_value_spans(text: str, whole: list[tuple[str, str]]) -> list[Span]:
    """Occurrences of declared-sensitive field values inside free text.

    Entity ``FIELD_<NAME>`` gives the same token as the field itself (same HMAC input),
    so the field and its mentions in text link up.
    """
    spans: list[Span] = []
    for name, value in whole:
        v = value.strip()
        if len(v) < 3:
            continue
        parts = [re.escape(p) for p in re.split(r"[\s\-.()/_]+", v) if p]
        rx = re.compile(r"(?<!\w)" + r"[\s\-.()/_]*".join(parts) + r"(?!\w)", re.IGNORECASE)
        spans += [Span(m.start(), m.end(), f"FIELD_{name.upper()}", 1.0)
                  for m in rx.finditer(text)]
    return spans


def _replace(text: str, spans: list[Span], tokens: list[str]) -> str:
    out, last = [], 0
    for s, tok in zip(spans, tokens, strict=True):
        out.append(text[last:s.start])
        out.append(tok)
        last = s.end
    out.append(text[last:])
    return "".join(out)


class IngestService:
    def __init__(self, settings: Settings, keyring: Keyring, tokenizer: Tokenizer,
                 detector: PiiDetector, embedder: Embedder, store: VectorStore,
                 policies: PolicyService, clock: Callable[[], float] = time.time) -> None:
        self._s = settings
        self._keyring = keyring
        self._tok = tokenizer
        self._det = detector
        self._emb = embedder
        self._store = store
        self._policies = policies
        self._clock = clock

    def _validate(self, req: IngestRequest) -> None:
        if len(req.fields) > self._s.max_fields or any(len(k) > 256 for k in req.fields):
            raise InvalidInputError
        if req.text is not None and len(req.text) > self._s.max_text_chars:
            raise InvalidInputError
        for v in req.fields.values():
            if isinstance(v, str) and len(v) > self._s.max_text_chars:
                raise InvalidInputError

    async def ingest(self, p: Principal, req: IngestRequest) -> IngestResult:
        self._validate(req)
        tenant = p.tenant_id
        if not await self._keyring.is_onboarded(tenant):
            raise TenantNotOnboardedError
        policy = await self._policies.get(tenant)

        # 1. Plan: which strings are scanned, which values are tokenized whole.
        kept: dict[str, Scalar] = {}
        scan_fields: list[str] = []
        whole: list[tuple[str, str]] = []  # (field, value)
        dropped = 0
        for name, value in req.fields.items():
            action = policy.action_for(name)
            if action == FieldAction.DROP:
                dropped += 1
            elif action == FieldAction.ALLOW:
                kept[name] = value
            elif value is None or isinstance(value, bool):
                kept[name] = value
            elif action == FieldAction.TOKENIZE:
                whole.append((name, str(value)))
            else:
                scan_fields.append(name)
                kept[name] = str(value)

        # 2. Detect (fails closed). Values the tenant declared sensitive (tokenize fields)
        #    are also swept from free text, so an NER miss on e.g. a rare name can't leak.
        texts = [str(kept[n]) for n in scan_fields] + ([req.text] if req.text else [])
        spans_per_text = [
            prefer_known(await self._det.detect(t), known_value_spans(t, whole)) for t in texts]

        # 3. Tokens for every finding in one HMAC-key access.
        items: list[tuple[str, str]] = [(f"FIELD_{n.upper()}", v) for n, v in whole]
        for t, spans in zip(texts, spans_per_text, strict=True):
            items.extend((s.entity, t[s.start:s.end]) for s in spans)
        tokens = await self._tok.tokens_for(tenant, items)

        vault: dict[str, tuple[str, str]] = {tok: it for tok, it in zip(tokens, items, strict=True)}
        it = iter(tokens)
        for n, _ in whole:
            kept[n] = next(it)
        tokenized_texts = []
        for t, spans in zip(texts, spans_per_text, strict=True):
            tokenized_texts.append(_replace(t, spans, [next(it) for _ in spans]))
        for n, t in zip(scan_fields, tokenized_texts[:len(scan_fields)], strict=True):
            kept[n] = t
        tok_text = tokenized_texts[-1] if req.text else None

        # 4. Vault first (idempotent), then the document + chunks in one transaction.
        await self._tok.store(tenant, vault)
        doc_id = DocumentId.new()
        ws = req.workspace_id
        original = json.dumps({"fields": req.fields, "text": req.text}).encode()
        tokenized = json.dumps({"fields": kept, "text": tok_text}).encode()
        enc_orig, enc_tok = await self._keyring.encrypt(tenant, ws, Purpose.DOCUMENT, [
            ({"doc_id": doc_id, "kind": "original"}, original),
            ({"doc_id": doc_id, "kind": "tokenized"}, tokenized)])

        body = "\n".join(f"{k}: {v}" for k, v in kept.items() if v is not None)
        if tok_text:
            body = f"{body}\n\n{tok_text}" if body else tok_text
        pieces = chunk_text(body, self._s.chunk_chars, self._s.chunk_overlap_chars)
        vecs = await self._emb.embed(pieces)
        chunk_ids = [ChunkId.new() for _ in pieces]
        enc_chunks = await self._keyring.encrypt(tenant, ws, Purpose.VECTOR, [
            ({"doc_id": doc_id, "chunk_id": cid, "seq": i, "kind": "chunk"},
             encode_chunk(piece, vecs[i]))
            for i, (cid, piece) in enumerate(zip(chunk_ids, pieces, strict=True))])
        await self._store.insert_document(
            DocumentRow(doc_id, tenant, ws, self._clock(), enc_orig.dek_id, enc_orig.nonce,
                        enc_orig.ciphertext, enc_tok.nonce, enc_tok.ciphertext),
            [ChunkRow(cid, doc_id, tenant, ws, i, x.dek_id, x.nonce, x.ciphertext)
             for i, (cid, x) in enumerate(zip(chunk_ids, enc_chunks, strict=True))])

        counts = Counter(e for e, _ in items)
        log.info("document_ingested", tenant_id=tenant, doc_id=doc_id, count=len(pieces))
        return IngestResult(doc_id, ws, len(pieces), dict(counts), dropped)

    async def get_document(self, p: Principal, doc_id: DocumentId, view: View) -> dict[str, Any]:
        row = await self._store.get_document(p.tenant_id, doc_id)
        if row is None:
            raise NotFoundError
        kind = view.value
        nonce, ct = ((row.original_nonce, row.original_ct) if view == View.ORIGINAL
                     else (row.tokenized_nonce, row.tokenized_ct))
        [pt] = await self._keyring.decrypt(p.tenant_id, row.dek_id,
                                           [({"doc_id": doc_id, "kind": kind}, nonce, ct)])
        data: dict[str, Any] = json.loads(pt)
        return {"doc_id": doc_id, "workspace_id": row.workspace_id, "view": kind, **data}

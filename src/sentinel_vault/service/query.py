"""Process (PLAN §6): agentic RAG query across the PHI boundary.

    question -> tokenize PII (same tenant key, so names in the question match stored tokens)
      -> embed -> load ONLY this tenant's chunks -> one KMS Decrypt per DEK (0 on cache hit)
      -> rank in memory -> top-k tokenized chunks -> EgressGuard -> LLM
      -> answer -> optional re-identification (scope ``reidentify``, tokens from this
         request's context only)

Tenant scoping happens before ranking, so a poisoned document can only ever see its
own tenant's chunks, and those are tokenized.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import Principal, Scope
from sentinel_vault.domain.ids import ChunkId, DocumentId, WorkspaceId
from sentinel_vault.persistence.vector_store import ChunkRow, VectorStore
from sentinel_vault.privacy.detector import PiiDetector
from sentinel_vault.privacy.egress import SYSTEM_PROMPT, EgressGuard, LlmClient
from sentinel_vault.retrieval.chunking import decode_chunk
from sentinel_vault.retrieval.embedder import Embedder
from sentinel_vault.security.errors import InvalidInputError, PermissionDeniedError
from sentinel_vault.security.logging import get_logger
from sentinel_vault.service.keyring import Keyring
from sentinel_vault.service.tokenization import TOKEN_RE, Tokenizer

log = get_logger(__name__)


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1)
    workspace_id: WorkspaceId = WorkspaceId("default")
    top_k: int = Field(default=5, ge=1)
    reidentify: bool = False


@dataclass(frozen=True, slots=True)
class Source:
    doc_id: DocumentId
    chunk_id: ChunkId
    score: float


@dataclass(frozen=True, slots=True)
class QueryResult:
    answer: str
    sources: list[Source]
    reidentified: bool
    egress_masked: int
    egress_blobs_removed: int


def chunk_aad(r: ChunkRow) -> dict[str, str | int]:
    return {"doc_id": r.doc_id, "chunk_id": r.chunk_id, "seq": r.seq, "kind": "chunk"}


class QueryService:
    def __init__(self, settings: Settings, keyring: Keyring, tokenizer: Tokenizer,
                 detector: PiiDetector, embedder: Embedder, store: VectorStore,
                 guard: EgressGuard, llm: LlmClient) -> None:
        self._s = settings
        self._keyring = keyring
        self._tok = tokenizer
        self._det = detector
        self._emb = embedder
        self._store = store
        self._guard = guard
        self._llm = llm

    async def _tokenize_question(self, p: Principal, q: str) -> str:
        spans = await self._det.detect(q)
        if not spans:
            return q
        items = [(s.entity, q[s.start:s.end]) for s in spans]
        toks = await self._tok.tokens_for(p.tenant_id, items)
        await self._tok.store(p.tenant_id, dict(zip(toks, items, strict=True)))
        out, last = [], 0
        for s, t in zip(spans, toks, strict=True):
            out += [q[last:s.start], t]
            last = s.end
        return "".join([*out, q[last:]])

    async def _load(self, p: Principal, ws: WorkspaceId) -> list[tuple[ChunkRow, str,
                                                                        np.ndarray]]:
        rows = await self._store.list_chunks(p.tenant_id, ws)
        by_dek: dict[str, list[ChunkRow]] = defaultdict(list)
        for r in rows:
            by_dek[r.dek_id].append(r)
        out = []
        for group in by_dek.values():  # one KMS Decrypt per DEK at most
            pts = await self._keyring.decrypt(p.tenant_id, group[0].dek_id,
                                              [(chunk_aad(r), r.nonce, r.ciphertext)
                                               for r in group])
            for r, pt in zip(group, pts, strict=True):
                text, vec = decode_chunk(pt)
                out.append((r, text, vec))
        return out

    async def query(self, p: Principal, req: QueryRequest) -> QueryResult:
        if len(req.question) > self._s.query_max_chars or req.top_k > self._s.query_max_top_k:
            raise InvalidInputError
        if req.reidentify and not p.has(Scope.REIDENTIFY):
            raise PermissionDeniedError
        question = await self._tokenize_question(p, req.question)
        chunks = await self._load(p, req.workspace_id)
        if not chunks:
            return QueryResult("No documents in this workspace.", [], False, 0, 0)
        [qv] = await self._emb.embed([question])
        mat = np.stack([v for _, _, v in chunks])
        scores = mat @ qv
        top = np.argsort(-scores, kind="stable")[: req.top_k]
        picked = [chunks[i] for i in top]

        prompt, stats = await self._guard.clean(p.tenant_id, SYSTEM_PROMPT,
                                                [t for _, t, _ in picked], question)
        answer = await self._llm.complete(prompt)

        reidentified = False
        if req.reidentify:
            allowed = {m.group(0) for t in prompt.texts() for m in TOKEN_RE.finditer(t)}
            wanted = [m.group(0) for m in TOKEN_RE.finditer(answer) if m.group(0) in allowed]
            mapping = await self._tok.reidentify(p.tenant_id, wanted)
            answer = TOKEN_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), answer)
            reidentified = True
        log.info("query_answered", tenant_id=p.tenant_id, count=len(picked))
        return QueryResult(
            answer,
            [Source(r.doc_id, r.chunk_id, round(float(scores[i]), 4))
             for i, (r, _, _) in zip(top, picked, strict=True)],
            reidentified, stats.masked, stats.blobs_removed)

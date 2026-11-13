"""Key rotation and compromise containment jobs (PLAN §8, §16). Resumable.

**Re-wrap** (after the customer rotates their CMK): ``ReEncrypt`` every wrapped DEK to the
current CMK version, inside the KMS. Payloads are untouched, the DEK never visits us, and
reads keep working the whole time because each row names its own DEK and version.
Each swap is a compare-and-swap; the cursor is saved after every batch. A crash or restart
resumes from the cursor; repeated work is skipped because the version is already current.

**Containment** (we suspect a tenant's DEKs or token key leaked):

1. Freeze the tenant: revoke every session, block logins. Flush cached keys.
2. Mark every live DEK ``compromised`` and record that set (one transaction).
3. New token key, new DEKs. Re-tokenize the vault under the new key.
4. Per document (one transaction each): decrypt, swap old tokens for new, re-embed
   chunks, re-encrypt under the new DEKs.
5. Delete old vault rows and the compromised wrapped DEKs. Unfreeze.

A leaked old DEK or token key then matches nothing we store. Only this tenant is touched.
On resume the recorded set is used, so keys made during containment aren't re-marked.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Coroutine
from typing import Any

from sentinel_vault.config import Settings
from sentinel_vault.domain.ids import DocumentId, TenantId
from sentinel_vault.persistence.keyring_store import DekState, JobRow, Purpose
from sentinel_vault.persistence.vault_store import VaultStore
from sentinel_vault.persistence.vector_store import ChunkRow, DocumentRow, VectorStore
from sentinel_vault.retrieval.chunking import decode_chunk, encode_chunk
from sentinel_vault.retrieval.embedder import Embedder
from sentinel_vault.security.errors import ConflictError, NotFoundError
from sentinel_vault.security.logging import get_logger
from sentinel_vault.service.auth_service import AuthService
from sentinel_vault.service.keyring import Keyring
from sentinel_vault.service.query import chunk_aad
from sentinel_vault.service.tokenization import TOKEN_RE, Tokenizer

log = get_logger(__name__)


class RotationService:
    def __init__(self, settings: Settings, keyring: Keyring, tokenizer: Tokenizer,
                 vectors: VectorStore, vault: VaultStore, embedder: Embedder,
                 auth: AuthService, clock: Callable[[], float] = time.time) -> None:
        self._s = settings
        self._kr = keyring
        self._store = keyring.store
        self._tok = tokenizer
        self._vec = vectors
        self._vault = vault
        self._emb = embedder
        self._auth = auth
        self._clock = clock
        self._tasks: set[asyncio.Task[None]] = set()

    # --- job plumbing -----------------------------------------------------------------

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _guarded(self, job: JobRow) -> None:
        try:
            await self.run(job)
        except Exception as exc:  # job stays "running" -> resumed on next start
            log.error("job_interrupted", tenant_id=job.tenant_id, error_type=type(exc).__name__,
                      exc_info=exc)

    async def _ensure_idle(self, tenant_id: TenantId) -> None:
        if any(j.tenant_id == tenant_id for j in await self._store.running_jobs()):
            raise ConflictError

    async def wait(self) -> None:
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def shutdown(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def resume_pending(self, background: bool = True) -> int:
        jobs = await self._store.running_jobs()
        for j in jobs:
            log.info("job_resumed", tenant_id=j.tenant_id, service=j.kind)
            if background:
                self._spawn(self._guarded(j))
            else:
                await self.run(j)
        return len(jobs)

    async def get_job(self, tenant_id: TenantId, job_id: str) -> JobRow:
        job = await self._store.get_job(tenant_id, job_id)
        if job is None:
            raise NotFoundError
        return job

    async def run(self, job: JobRow) -> None:
        if job.kind == "rewrap":
            await self._run_rewrap(job)
        else:
            await self._run_contain(job)

    # --- re-wrap --------------------------------------------------------------------------

    async def start_rewrap(self, tenant_id: TenantId, background: bool = True) -> str:
        await self._ensure_idle(tenant_id)
        job_id = f"job_{uuid.uuid4().hex}"
        await self._store.create_job(job_id, tenant_id, "rewrap", "rewrap", {}, self._clock())
        job = await self.get_job(tenant_id, job_id)
        if background:
            self._spawn(self._guarded(job))
        else:
            await self.run(job)
        return job_id

    async def _run_rewrap(self, job: JobRow) -> None:
        t, cursor = job.tenant_id, job.cursor
        while True:
            batch = await self._store.deks_after(t, cursor, self._s.job_batch_size)
            if not batch:
                break
            done = 0
            for d in batch:
                if d.state == DekState.COMPROMISED:
                    continue
                blob, version = await self._kr.rewrap(d)
                if version > d.cmk_version and await self._store.cas_rewrap(
                        t, d.dek_id, d.wrapped, blob, version):
                    done += 1
            cursor = batch[-1].dek_id
            await self._store.update_job(job.job_id, self._clock(), cursor=cursor,
                                         add_processed=done)
        await self._store.update_job(job.job_id, self._clock(), state="done", step="done")
        log.info("rewrap_done", tenant_id=t)

    # --- containment -------------------------------------------------------------------------

    async def start_containment(self, tenant_id: TenantId, background: bool = True) -> str:
        await self._ensure_idle(tenant_id)
        await self._auth.freeze_tenant(tenant_id)
        self._kr.flush_tenant(tenant_id)
        job_id = f"job_{uuid.uuid4().hex}"
        ids = await self._store.start_containment(job_id, tenant_id, self._clock())
        log.warning("containment_started", tenant_id=tenant_id, count=len(ids))
        job = await self.get_job(tenant_id, job_id)
        if background:
            self._spawn(self._guarded(job))
        else:
            await self.run(job)
        return job_id

    async def _token_mapping(self, t: TenantId, old: list[str]) -> dict[str, str]:
        rows = await self._vault.rows_on_deks(t, old)
        by_dek: dict[str, list[Any]] = defaultdict(list)
        for r in rows:
            by_dek[r.dek_id].append(r)
        mapping: dict[str, str] = {}
        for group in by_dek.values():
            vals = await self._kr.decrypt(t, group[0].dek_id, [
                ({"token": r.token, "entity": r.entity, "kind": "vault"}, r.nonce, r.ciphertext)
                for r in group])
            items = [(r.entity, v.decode()) for r, v in zip(group, vals, strict=True)]
            new = await self._tok.tokens_for(t, items)  # new token key (old one compromised)
            await self._tok.store(t, dict(zip(new, items, strict=True)))
            mapping.update({r.token: n for r, n in zip(group, new, strict=True)})
        return mapping

    async def _migrate_doc(self, t: TenantId, doc_id: DocumentId,
                           mapping: dict[str, str]) -> None:
        row = await self._vec.get_document(t, doc_id)
        if row is None:  # pragma: no cover - deleted concurrently
            return
        orig, tok = await self._kr.decrypt(t, row.dek_id, [
            ({"doc_id": doc_id, "kind": "original"}, row.original_nonce, row.original_ct),
            ({"doc_id": doc_id, "kind": "tokenized"}, row.tokenized_nonce, row.tokenized_ct)])

        def swap(s: str) -> str:
            return TOKEN_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), s)

        tok_new = json.dumps(json.loads(swap(tok.decode()))).encode()
        chunks = await self._vec.chunks_for_doc(t, doc_id)
        by_dek: dict[str, list[ChunkRow]] = defaultdict(list)
        for c in chunks:
            by_dek[c.dek_id].append(c)
        texts: dict[str, str] = {}
        for group in by_dek.values():
            pts = await self._kr.decrypt(t, group[0].dek_id, [
                (chunk_aad(c), c.nonce, c.ciphertext) for c in group])
            for c, pt in zip(group, pts, strict=True):
                texts[c.chunk_id] = swap(decode_chunk(pt)[0])
        ordered = sorted(chunks, key=lambda c: c.seq)
        vecs = await self._emb.embed([texts[c.chunk_id] for c in ordered])
        ws = row.workspace_id
        enc_o, enc_t = await self._kr.encrypt(t, ws, Purpose.DOCUMENT, [
            ({"doc_id": doc_id, "kind": "original"}, orig),
            ({"doc_id": doc_id, "kind": "tokenized"}, tok_new)])
        enc_c = await self._kr.encrypt(t, ws, Purpose.VECTOR, [
            (chunk_aad(c), encode_chunk(texts[c.chunk_id], vecs[i]))
            for i, c in enumerate(ordered)])
        await self._vec.replace_document(
            DocumentRow(doc_id, t, ws, row.created_at, enc_o.dek_id, enc_o.nonce,
                        enc_o.ciphertext, enc_t.nonce, enc_t.ciphertext),
            [ChunkRow(c.chunk_id, doc_id, t, c.workspace_id, c.seq, x.dek_id, x.nonce,
                      x.ciphertext) for c, x in zip(ordered, enc_c, strict=True)])

    async def _run_contain(self, job: JobRow) -> None:
        t = job.tenant_id
        old: list[str] = list(job.data["compromised"])
        await self._auth.freeze_tenant(t)  # idempotent; also on resume
        if job.step == "migrate":
            mapping = await self._token_mapping(t, old)
            while True:
                docs = await self._vec.documents_on_deks(t, old, self._s.job_batch_size)
                if not docs:
                    break
                for d in docs:
                    await self._migrate_doc(t, d, mapping)
                await self._store.update_job(job.job_id, self._clock(), add_processed=len(docs))
            await self._store.update_job(job.job_id, self._clock(), step="cleanup")
        await self._vault.delete_on_deks(t, old)
        await self._store.delete_deks(t, old)
        self._kr.flush_tenant(t)
        await self._store.update_job(job.job_id, self._clock(), state="done", step="done")
        await self._auth.unfreeze_tenant(t)
        log.warning("containment_done", tenant_id=t, count=len(old))

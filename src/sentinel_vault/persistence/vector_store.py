"""``vector.db``: encrypted documents and chunks. Holds no keys.

Every method takes ``tenant_id`` and filters by it. There is no method that reads across
tenants. AAD (tenant, doc, chunk, DEK) is the cryptographic backstop if a row is moved.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import (
    Column,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    and_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel_vault.domain.ids import ChunkId, DekId, DocumentId, TenantId, WorkspaceId

metadata = MetaData()

documents = Table(
    "documents", metadata,
    Column("doc_id", String(40), primary_key=True),
    Column("tenant_id", String(32), nullable=False),
    Column("workspace_id", String(32), nullable=False),
    Column("created_at", Float, nullable=False),
    Column("dek_id", String(40), nullable=False),
    Column("original_nonce", LargeBinary, nullable=False),
    Column("original_ct", LargeBinary, nullable=False),
    Column("tokenized_nonce", LargeBinary, nullable=False),
    Column("tokenized_ct", LargeBinary, nullable=False),
    Index("ix_documents_tenant", "tenant_id", "workspace_id"),
)

chunks = Table(
    "chunks", metadata,
    Column("chunk_id", String(40), primary_key=True),
    Column("doc_id", String(40), nullable=False),
    Column("tenant_id", String(32), nullable=False),
    Column("workspace_id", String(32), nullable=False),
    Column("seq", Integer, nullable=False),
    Column("dek_id", String(40), nullable=False),
    Column("nonce", LargeBinary, nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    ForeignKeyConstraint(["doc_id"], ["documents.doc_id"], ondelete="CASCADE"),
    Index("ix_chunks_tenant", "tenant_id", "workspace_id"),
)


@dataclass(frozen=True, slots=True)
class DocumentRow:
    doc_id: DocumentId
    tenant_id: TenantId
    workspace_id: WorkspaceId
    created_at: float
    dek_id: DekId
    original_nonce: bytes
    original_ct: bytes
    tokenized_nonce: bytes
    tokenized_ct: bytes


@dataclass(frozen=True, slots=True)
class ChunkRow:
    chunk_id: ChunkId
    doc_id: DocumentId
    tenant_id: TenantId
    workspace_id: WorkspaceId
    seq: int
    dek_id: DekId
    nonce: bytes
    ciphertext: bytes


class VectorStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def create_schema(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def insert_document(self, doc: DocumentRow, rows: list[ChunkRow]) -> None:
        """Document and all its chunks in one transaction."""
        async with self._engine.begin() as conn:
            await conn.execute(documents.insert().values(
                doc_id=doc.doc_id, tenant_id=doc.tenant_id, workspace_id=doc.workspace_id,
                created_at=doc.created_at, dek_id=doc.dek_id,
                original_nonce=doc.original_nonce, original_ct=doc.original_ct,
                tokenized_nonce=doc.tokenized_nonce, tokenized_ct=doc.tokenized_ct))
            if rows:
                await conn.execute(chunks.insert(), [
                    {"chunk_id": c.chunk_id, "doc_id": c.doc_id, "tenant_id": c.tenant_id,
                     "workspace_id": c.workspace_id, "seq": c.seq, "dek_id": c.dek_id,
                     "nonce": c.nonce, "ciphertext": c.ciphertext} for c in rows])

    async def get_document(self, tenant_id: TenantId, doc_id: DocumentId) -> DocumentRow | None:
        async with self._engine.begin() as conn:
            r = (await conn.execute(select(documents).where(and_(
                documents.c.doc_id == doc_id, documents.c.tenant_id == tenant_id)))).first()
        if r is None:
            return None
        m = r._mapping
        return DocumentRow(DocumentId(m["doc_id"]), TenantId(m["tenant_id"]),
                           WorkspaceId(m["workspace_id"]), m["created_at"], DekId(m["dek_id"]),
                           bytes(m["original_nonce"]), bytes(m["original_ct"]),
                           bytes(m["tokenized_nonce"]), bytes(m["tokenized_ct"]))

    async def list_chunks(self, tenant_id: TenantId,
                          workspace_id: WorkspaceId | None = None) -> list[ChunkRow]:
        cond = chunks.c.tenant_id == tenant_id
        if workspace_id is not None:
            cond = and_(cond, chunks.c.workspace_id == workspace_id)
        async with self._engine.begin() as conn:
            rows = (await conn.execute(select(chunks).where(cond)
                                       .order_by(chunks.c.doc_id, chunks.c.seq))).all()
        return [ChunkRow(ChunkId(m["chunk_id"]), DocumentId(m["doc_id"]),
                         TenantId(m["tenant_id"]), WorkspaceId(m["workspace_id"]), m["seq"],
                         DekId(m["dek_id"]), bytes(m["nonce"]), bytes(m["ciphertext"]))
                for m in (r._mapping for r in rows)]

    async def count_documents(self, tenant_id: TenantId) -> int:
        async with self._engine.begin() as conn:
            return len((await conn.execute(select(documents.c.doc_id).where(
                documents.c.tenant_id == tenant_id))).all())

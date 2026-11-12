from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from sentinel_vault.domain.ids import ChunkId, DekId, DocumentId, SessionId, TenantId, UserId


class Ref(BaseModel):
    tenant: TenantId
    doc: DocumentId


@pytest.mark.parametrize("good", ["acme", "st-marys-hospital", "a1b"])
def test_tenant_ok(good: str) -> None:
    assert TenantId(good) == good


@pytest.mark.parametrize(
    "bad",
    ["", "ab", "Acme", "acme-", "-acme", "acme/../beta", "acme' OR 1=1--", "аcme",  # Cyrillic а
     "a" * 40, "acme\n", "acme beta"],
)
def test_tenant_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        TenantId(bad)


def test_prefixed_ids_cannot_cross_kinds() -> None:
    d = DocumentId.new()
    assert d.startswith("doc_")
    with pytest.raises(ValueError):
        ChunkId(d)
    with pytest.raises(ValueError):
        DekId(ChunkId.new())
    assert SessionId.new() != SessionId.new()


def test_user_id() -> None:
    assert UserId("dr.alice-01") == "dr.alice-01"
    with pytest.raises(ValueError):
        UserId("Alice@x")


def test_pydantic_parses_and_serializes() -> None:
    d = DocumentId.new()
    r = Ref.model_validate({"tenant": "acme", "doc": str(d)})
    assert isinstance(r.tenant, TenantId)
    assert isinstance(r.doc, DocumentId)
    assert r.model_dump() == {"tenant": "acme", "doc": str(d)}


@pytest.mark.parametrize("doc", ["doc_123", "chk_" + "0" * 32, "doc_" + "G" * 32, 42])
def test_pydantic_rejects_bad_ids(doc: object) -> None:
    with pytest.raises(ValidationError):
        Ref.model_validate({"tenant": "acme", "doc": doc})

"""Reversible tokenization + vault (PLAN §7).

Token = ``<<ENTITY_<16 hex>>>`` where hex = HMAC-SHA256(tenant token key,
entity | normalized value)[:8 bytes].

- Same value -> same token within a tenant, so joins and repeated mentions still line up.
- Different tenants -> different tokens (different HMAC keys): tokens can't be correlated
  across tenants.
- The HMAC key is a DEK wrapped by the tenant's CMK. Revoking the CMK stops new tokens
  and re-identification.
- Original values sit in ``vault.db``, AES-GCM encrypted under a tenant VAULT DEK with
  AAD binding (token, entity).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from typing import Final

from sentinel_vault.domain.ids import TenantId, WorkspaceId
from sentinel_vault.persistence.keyring_store import Purpose
from sentinel_vault.persistence.vault_store import VaultRow, VaultStore
from sentinel_vault.privacy.normalize import normalize
from sentinel_vault.service.keyring import Keyring

TOKEN_RE: Final = re.compile(r"<<([A-Z][A-Z0-9_]{1,47})_([0-9a-f]{16})>>")
VAULT_WS: Final = WorkspaceId("tenant-wide")
_SQUASH: Final = re.compile(r"[\s\-.()/_]+")


def normalize_value(value: str) -> str:
    return _SQUASH.sub("", normalize(value).casefold())


def make_token(key: bytes | bytearray, entity: str, value: str) -> str:
    mac = hmac.new(bytes(key), f"{entity}|{normalize_value(value)}".encode(), hashlib.sha256)
    return f"<<{entity}_{mac.hexdigest()[:16]}>>"


class Tokenizer:
    def __init__(self, keyring: Keyring, vault: VaultStore,
                 clock: Callable[[], float] = time.time) -> None:
        self._keyring = keyring
        self._vault = vault
        self._clock = clock

    async def tokens_for(self, tenant_id: TenantId,
                         items: Sequence[tuple[str, str]]) -> list[str]:
        """(entity, original value) -> token, using one key access for the whole batch."""
        if not items:
            return []
        return await self._keyring.token_key_use(
            tenant_id, lambda key: [make_token(key, e, v) for e, v in items])

    async def store(self, tenant_id: TenantId, entries: dict[str, tuple[str, str]]) -> int:
        """Persist token -> (entity, original). Skips tokens already in the vault."""
        known = await self._vault.existing_tokens(tenant_id, list(entries))
        new = [(t, e, v) for t, (e, v) in entries.items() if t not in known]
        if not new:
            return 0
        enc = await self._keyring.encrypt(
            tenant_id, VAULT_WS, Purpose.VAULT,
            [({"token": t, "entity": e, "kind": "vault"}, v.encode()) for t, e, v in new])
        await self._vault.insert_many(
            [VaultRow(tenant_id, t, e, x.dek_id, x.nonce, x.ciphertext)
             for (t, e, _), x in zip(new, enc, strict=True)], self._clock())
        return len(new)

    async def reidentify(self, tenant_id: TenantId, tokens: Sequence[str]) -> dict[str, str]:
        """Token -> original value, for this tenant only. Unknown tokens are omitted."""
        rows = await self._vault.get_many(tenant_id, sorted(set(tokens)))
        by_dek: dict[str, list[VaultRow]] = defaultdict(list)
        for r in rows:
            by_dek[r.dek_id].append(r)
        out: dict[str, str] = {}
        for group in by_dek.values():
            vals = await self._keyring.decrypt(tenant_id, group[0].dek_id, [
                ({"token": r.token, "entity": r.entity, "kind": "vault"}, r.nonce, r.ciphertext)
                for r in group])
            out.update({r.token: v.decode() for r, v in zip(group, vals, strict=True)})
        return out

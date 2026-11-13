"""Keyring: the only code that touches data keys (PLAN §4, §16).

- One active DEK per (tenant, workspace, purpose). Rolled at max uses or max age.
- DEK wrapped by the **tenant's own CMK** in the customer KMS, with encryption context
  ``{tenant_id, workspace_id, purpose, dek_id}``. The customer's key policy checks
  ``tenant_id``, so a wrong-tenant unwrap fails outside our code too.
- Payload AAD always includes ``tenant_id``, ``workspace_id``, ``dek_id`` and ``alg``,
  added here so callers can't leave them out.
- Plaintext DEKs live only in the cache (bytearray, zeroed on eviction).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from sentinel_vault.config import Settings
from sentinel_vault.crypto.dek_cache import DekCache
from sentinel_vault.crypto.envelope import (
    ALG,
    SCHEMA_VERSION,
    AadValue,
    DecryptionError,
    Sealed,
    canonical_aad,
    open_sealed,
    seal,
)
from sentinel_vault.crypto.wipe import wipe
from sentinel_vault.domain.ids import DekId, TenantId, WorkspaceId
from sentinel_vault.kms_client.provider import (
    DataIntegrityError,
    KmsProvider,
    TenantKeyRef,
)
from sentinel_vault.persistence.keyring_store import (
    DekRow,
    DekState,
    KeyringStore,
    Purpose,
    TenantKeyRow,
)
from sentinel_vault.security.errors import AppError, NotFoundError
from sentinel_vault.security.logging import get_logger

log = get_logger(__name__)

PROBE_WORKSPACE = WorkspaceId("onboarding-probe")


class TenantNotOnboardedError(AppError):
    status_code = 409
    code = "tenant_not_onboarded"
    public_message = "Tenant has no encryption key configured."


@dataclass(frozen=True, slots=True)
class EncryptedItem:
    dek_id: DekId
    nonce: bytes
    ciphertext: bytes


def kms_context(dek: DekRow | tuple[TenantId, WorkspaceId, Purpose, DekId]) -> dict[str, str]:
    if isinstance(dek, DekRow):
        t, w, p, d = dek.tenant_id, dek.workspace_id, dek.purpose, dek.dek_id
    else:
        t, w, p, d = dek
    return {"tenant_id": t, "workspace_id": w, "purpose": p.value, "dek_id": d}


class Keyring:
    def __init__(self, store: KeyringStore, kms: KmsProvider, cache: DekCache,
                 settings: Settings, clock: Callable[[], float] = time.time) -> None:
        self._store = store
        self._kms = kms
        self.cache = cache
        self._s = settings
        self._clock = clock
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}

    # --- onboarding -------------------------------------------------------------------

    async def onboard(self, tenant_id: TenantId, kms_account: str, cmk_id: str) -> None:
        """BYOK handshake: prove we can GenerateDataKey + Decrypt before accepting the CMK."""
        ref = TenantKeyRef(kms_account, cmk_id)
        probe_id = DekId.new()
        ctx = kms_context((tenant_id, PROBE_WORKSPACE, Purpose.VECTOR, probe_id))
        gen = await self._kms.generate_data_key(ref, ctx)
        back = await self._kms.decrypt(ref, gen.wrapped, ctx)
        ok = back == gen.plaintext
        wipe(gen.plaintext)
        wipe(back)
        if not ok:  # pragma: no cover - would mean a broken KMS
            raise DataIntegrityError
        await self._store.set_tenant_key(TenantKeyRow(tenant_id, kms_account, cmk_id),
                                         self._clock())
        log.info("tenant_onboarded", tenant_id=tenant_id, cmk_id=cmk_id)

    async def _ref(self, tenant_id: TenantId) -> TenantKeyRef:
        row = await self._store.get_tenant_key(tenant_id)
        if row is None:
            raise TenantNotOnboardedError
        return TenantKeyRef(row.kms_account, row.cmk_id)

    async def is_onboarded(self, tenant_id: TenantId) -> bool:
        return await self._store.get_tenant_key(tenant_id) is not None

    # --- DEK lifecycle ------------------------------------------------------------------

    def _expired(self, d: DekRow, extra_uses: int) -> bool:
        if d.purpose == Purpose.TOKEN_KEY:  # stable HMAC key: rolling it changes tokens
            return False
        return (d.uses + extra_uses > self._s.dek_max_uses
                or self._clock() - d.created_at > self._s.dek_max_age_seconds)

    async def _active(self, tenant_id: TenantId, ws: WorkspaceId, purpose: Purpose,
                      uses: int) -> DekRow:
        lock = self._locks.setdefault((tenant_id, ws, purpose.value), asyncio.Lock())
        async with lock:
            cur = await self._store.active_dek(tenant_id, ws, purpose)
            if cur is not None and not self._expired(cur, uses):
                return cur
            ref = await self._ref(tenant_id)
            dek_id = DekId.new()
            gen = await self._kms.generate_data_key(
                ref, kms_context((tenant_id, ws, purpose, dek_id)))
            row = DekRow(dek_id, tenant_id, ws, purpose, gen.wrapped, gen.cmk_version, 0,
                         self._clock(), DekState.ACTIVE)
            await self._store.insert_dek(row, retire=cur.dek_id if cur else None)
            self.cache.put(tenant_id, dek_id, gen.plaintext)
            log.info("dek_created", tenant_id=tenant_id, workspace_id=ws, dek_id=dek_id,
                     service=purpose.value)
            return row

    async def _loader(self, d: DekRow) -> bytearray:
        ref = await self._ref(d.tenant_id)
        return await self._kms.decrypt(ref, d.wrapped, kms_context(d))

    @staticmethod
    def _aad(d: DekRow, fields: Mapping[str, AadValue]) -> bytes:
        reserved = {"tenant_id", "workspace_id", "dek_id", "alg", "v", "purpose"}
        if reserved & fields.keys():
            raise ValueError("AAD fields may not override reserved names")
        return canonical_aad({**fields, "tenant_id": d.tenant_id, "workspace_id": d.workspace_id,
                              "dek_id": d.dek_id, "purpose": d.purpose.value, "alg": ALG,
                              "v": SCHEMA_VERSION})

    # --- encrypt / decrypt ----------------------------------------------------------------

    async def encrypt(self, tenant_id: TenantId, ws: WorkspaceId, purpose: Purpose,
                      items: Sequence[tuple[Mapping[str, AadValue], bytes]]
                      ) -> list[EncryptedItem]:
        if not items:
            return []
        d = await self._active(tenant_id, ws, purpose, len(items))

        def run(key: bytearray) -> list[EncryptedItem]:
            out = []
            for fields, pt in items:
                s = seal(key, pt, self._aad(d, fields))
                out.append(EncryptedItem(d.dek_id, s.nonce, s.ciphertext))
            return out

        result = await self.cache.use(tenant_id, d.dek_id, lambda: self._loader(d), run,
                                      uses=len(items))
        await self._store.add_uses(tenant_id, d.dek_id, len(items))
        return result

    async def decrypt(self, tenant_id: TenantId, dek_id: DekId,
                      items: Sequence[tuple[Mapping[str, AadValue], bytes, bytes]]
                      ) -> list[bytes]:
        """Items are (aad_fields, nonce, ciphertext). The DEK must belong to ``tenant_id``."""
        d = await self._store.get_dek(tenant_id, dek_id)
        if d is None:
            raise NotFoundError
        if d.state == DekState.COMPROMISED:
            log.warning("compromised_dek_read", tenant_id=tenant_id, dek_id=dek_id)

        def run(key: bytearray) -> list[bytes]:
            try:
                return [open_sealed(key, Sealed(n, c), self._aad(d, f)) for f, n, c in items]
            except DecryptionError as exc:
                log.error("payload_integrity_failure", tenant_id=tenant_id, dek_id=dek_id)
                raise DataIntegrityError from exc

        return await self.cache.use(tenant_id, dek_id, lambda: self._loader(d), run,
                                    uses=len(items))

    async def token_key_use[T](self, tenant_id: TenantId, fn: Callable[[bytearray], T]) -> T:
        """Run ``fn`` with the tenant's stable tokenization HMAC key."""
        d = await self._active(tenant_id, WorkspaceId("tenant-wide"), Purpose.TOKEN_KEY, 0)
        return await self.cache.use(tenant_id, d.dek_id, lambda: self._loader(d), fn)

    def flush_tenant(self, tenant_id: TenantId) -> int:
        """Drop every cached key for a tenant now (customer revocation, containment)."""
        return self.cache.evict_tenant(tenant_id)

    @property
    def store(self) -> KeyringStore:
        return self._store

    async def rewrap(self, d: DekRow) -> tuple[bytes, int]:
        """ReEncrypt a wrapped DEK under the CMK's current version. No plaintext here."""
        ref = await self._ref(d.tenant_id)
        return await self._kms.re_encrypt(ref, d.wrapped, kms_context(d))

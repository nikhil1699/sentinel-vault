"""``KmsProvider``: how our service talks to a tenant's KMS.

``SignedKmsProvider`` uses the simulated customer KMS. An AWS KMS adapter would
implement the same protocol (GenerateDataKey / Decrypt / ReEncrypt with an encryption
context and a cross-account key ARN).

Failure mapping is fail-closed:
- access denied / key disabled / deleted -> ``TenantKeyUnavailableError`` (nothing served)
- invalid ciphertext -> ``DataIntegrityError`` (tamper signal)
- transport errors / KMS 5xx -> retried, then ``DependencyUnavailableError``
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, TypeVar

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from customer_kms.client import KmsClient, KmsError
from sentinel_vault.security.errors import AppError, DependencyUnavailableError
from sentinel_vault.security.logging import get_logger

log = get_logger(__name__)
T = TypeVar("T")


class TenantKeyUnavailableError(AppError):
    """The customer revoked, disabled or deleted our access to their key."""

    status_code = 503
    code = "tenant_key_unavailable"
    public_message = "The tenant's encryption key is not available."


class DataIntegrityError(AppError):
    """Stored ciphertext or wrapped key failed authentication. Possible tampering."""

    status_code = 500
    code = "integrity_error"
    public_message = "Stored data failed an integrity check."


@dataclass(frozen=True, slots=True)
class TenantKeyRef:
    kms_account: str
    cmk_id: str


@dataclass(slots=True)
class GeneratedKey:
    plaintext: bytearray
    wrapped: bytes
    cmk_version: int


class KmsProvider(Protocol):
    async def generate_data_key(self, ref: TenantKeyRef,
                                ctx: Mapping[str, str]) -> GeneratedKey: ...

    async def decrypt(self, ref: TenantKeyRef, wrapped: bytes,
                      ctx: Mapping[str, str]) -> bytearray: ...

    async def re_encrypt(self, ref: TenantKeyRef, wrapped: bytes,
                         ctx: Mapping[str, str]) -> tuple[bytes, int]: ...


_UNAVAILABLE = {"access_denied", "key_unavailable", "unauthenticated", "not_found"}


class SignedKmsProvider:
    def __init__(self, http: httpx.AsyncClient, principal: str,
                 private_key: Ed25519PrivateKey, max_retries: int = 2,
                 clock: Callable[[], float] | None = None) -> None:
        self._http = http
        self._principal = principal
        self._key = private_key
        self._retries = max_retries
        self._clock = clock
        self.calls = 0  # observability for tests: real KMS round trips

    def _client(self, ref: TenantKeyRef) -> KmsClient:
        if self._clock is None:
            return KmsClient(self._http, account=ref.kms_account, principal=self._principal,
                             private_key=self._key)
        return KmsClient(self._http, account=ref.kms_account, principal=self._principal,
                         private_key=self._key, clock=self._clock)

    async def _call(self, op: str, fn: Callable[[], Awaitable[T]]) -> T:
        delay = 0.05
        for attempt in range(self._retries + 1):
            self.calls += 1
            try:
                return await fn()
            except KmsError as exc:
                if exc.code in _UNAVAILABLE:
                    log.warning("kms_denied", error_code=exc.code, service=op)
                    raise TenantKeyUnavailableError from exc
                if exc.code == "invalid_ciphertext":
                    log.error("kms_invalid_ciphertext", service=op)
                    raise DataIntegrityError from exc
                if exc.status < 500 or attempt == self._retries:
                    log.error("kms_error", error_code=exc.code, status=exc.status, service=op)
                    raise DependencyUnavailableError from exc
            except httpx.TransportError as exc:
                if attempt == self._retries:
                    log.error("kms_unreachable", service=op, error_type=type(exc).__name__)
                    raise DependencyUnavailableError from exc
            await asyncio.sleep(delay)
            delay *= 4
        raise DependencyUnavailableError  # pragma: no cover

    async def generate_data_key(self, ref: TenantKeyRef,
                                ctx: Mapping[str, str]) -> GeneratedKey:
        dk = await self._call("GenerateDataKey",
                              lambda: self._client(ref).generate_data_key(ref.cmk_id, ctx))
        return GeneratedKey(dk.plaintext, dk.ciphertext_blob, dk.cmk_version)

    async def decrypt(self, ref: TenantKeyRef, wrapped: bytes,
                      ctx: Mapping[str, str]) -> bytearray:
        return await self._call("Decrypt", lambda: self._client(ref).decrypt(wrapped, ctx))

    async def re_encrypt(self, ref: TenantKeyRef, wrapped: bytes,
                         ctx: Mapping[str, str]) -> tuple[bytes, int]:
        return await self._call("ReEncrypt",
                                lambda: self._client(ref).re_encrypt(wrapped, ctx))

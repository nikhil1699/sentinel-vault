"""Customer KMS operations (PLAN §15).

Every request: authenticate (signature, skew, nonce) -> authorize (admin-only, or key
policy for crypto ops) -> check key state -> do work -> append to the account's audit
chain. Denials and failures are audited too, so a customer sees every attempt we make.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from customer_kms import crypto
from customer_kms.directory import AccountInfo, load_account, load_principal
from customer_kms.errors import (
    KmsAccessDeniedError,
    KmsAuthError,
    KmsInvalidCiphertextError,
    KmsInvalidRequestError,
    KmsKeyUnavailableError,
    KmsNotFoundError,
)
from customer_kms.policy import CryptoAction, KeyPolicy, evaluate
from customer_kms.protocol import (
    H_ACCOUNT,
    H_DATE,
    H_NONCE,
    H_PRINCIPAL,
    H_SIGNATURE,
    MAX_SKEW_SECONDS,
    NAME_RE,
    NONCE_RE,
    InvalidContextError,
    canonical_context,
    validate_context,
    verify_signature,
)
from customer_kms.store import AccountStore, AuditEntry, KeyRow, KeyState
from sentinel_vault.persistence.sqlite import create_sqlite_engine
from sentinel_vault.security.errors import AppError
from sentinel_vault.security.logging import get_logger

log = get_logger(__name__)
T = TypeVar("T")
Clock = Callable[[], float]

MIN_PENDING_DAYS, MAX_PENDING_DAYS = 7, 30
_CMK_RE_PREFIX = "cmk_"


@dataclass(frozen=True, slots=True)
class Caller:
    account: str
    principal: str
    is_admin: bool


@dataclass(frozen=True, slots=True)
class DataKey:
    plaintext: bytes
    ciphertext_blob: bytes
    cmk_id: str
    cmk_version: int


@dataclass(slots=True)
class _Account:
    info: AccountInfo
    root: bytes
    store: AccountStore
    lock: asyncio.Lock


def _valid_cmk_id(cmk_id: str) -> bool:
    if not cmk_id.startswith(_CMK_RE_PREFIX) or len(cmk_id) != 36:
        return False
    try:
        return uuid.UUID(hex=cmk_id[4:]).hex == cmk_id[4:]
    except ValueError:
        return False


class KmsService:
    def __init__(self, data_dir: Path, clock: Clock = time.time) -> None:
        self._dir = data_dir
        self._clock = clock
        self._accounts: dict[str, _Account] = {}
        self._open_lock = asyncio.Lock()

    async def close(self) -> None:
        for acct in self._accounts.values():
            await acct.store.dispose()
        self._accounts.clear()

    async def _account(self, account: str) -> _Account | None:
        if account in self._accounts:
            return self._accounts[account]
        async with self._open_lock:
            if account in self._accounts:
                return self._accounts[account]
            info = load_account(self._dir, account)
            if info is None:
                return None
            root = crypto.load_or_create_root_key(info.path / "root.key")
            store = AccountStore(create_sqlite_engine(info.path / "kms.db"))
            await store.create_schema()
            acct = _Account(info, root, store, asyncio.Lock())
            self._accounts[account] = acct
            return acct

    # --- authentication -------------------------------------------------------------

    async def authenticate(self, method: str, path: str, headers: Mapping[str, str],
                           body: bytes) -> Caller:
        account = headers.get(H_ACCOUNT, "")
        principal = headers.get(H_PRINCIPAL, "")
        date = headers.get(H_DATE, "")
        nonce = headers.get(H_NONCE, "")
        sig = headers.get(H_SIGNATURE, "")
        if not (NAME_RE.fullmatch(account) and NAME_RE.fullmatch(principal)
                and NONCE_RE.fullmatch(nonce) and date.isdigit() and len(date) <= 12):
            raise KmsAuthError
        acct = await self._account(account)
        if acct is None:
            raise KmsAuthError
        is_admin = principal == acct.info.admin_principal
        pub = acct.info.admin_public_key if is_admin else load_principal(self._dir, principal)
        if pub is None:
            raise KmsAuthError
        if not verify_signature(pub, sig, method=method, path=path, account=account,
                                principal=principal, date=date, nonce=nonce, body=body):
            await self._audit(acct, principal, "Authenticate", None, "deny", "bad_signature")
            raise KmsAuthError
        now = self._clock()
        if abs(now - int(date)) > MAX_SKEW_SECONDS:
            await self._audit(acct, principal, "Authenticate", None, "deny", "clock_skew")
            raise KmsAuthError
        if not await acct.store.use_nonce(principal, nonce, now, now + 2 * MAX_SKEW_SECONDS):
            await self._audit(acct, principal, "Authenticate", None, "deny", "replay")
            raise KmsAuthError
        return Caller(account, principal, is_admin)

    # --- helpers ---------------------------------------------------------------------

    async def _audit(self, acct: _Account, principal: str, op: str, cmk_id: str | None,
                     outcome: str, reason: str, ctx: Mapping[str, str] | None = None) -> None:
        await acct.store.append_audit(ts=self._clock(), principal=principal, operation=op,
                                      cmk_id=cmk_id, outcome=outcome, reason=reason,
                                      context=dict(ctx or {}))

    async def _get_acct(self, c: Caller) -> _Account:
        acct = await self._account(c.account)
        if acct is None:  # pragma: no cover - authenticate() already checked
            raise KmsAuthError
        return acct

    async def _audited(self, c: Caller, op: str, cmk_id: str | None,
                       ctx: Mapping[str, str] | None,
                       fn: Callable[[_Account], Awaitable[tuple[T, str]]]) -> T:
        acct = await self._get_acct(c)
        try:
            result, reason = await fn(acct)
        except AppError as exc:
            outcome = "deny" if isinstance(exc, KmsAccessDeniedError) else "error"
            await self._audit(acct, c.principal, op, cmk_id, outcome,
                              getattr(exc, "audit_reason", exc.code), ctx)
            raise
        await self._audit(acct, c.principal, op, cmk_id, "allow", reason, ctx)
        return result

    async def _load_key(self, acct: _Account, cmk_id: str) -> KeyRow | None:
        if not _valid_cmk_id(cmk_id):
            return None
        key = await acct.store.get_key(cmk_id)
        if (key is not None and key.state == KeyState.PENDING_DELETION
                and key.deletion_date is not None and self._clock() >= key.deletion_date):
            await acct.store.destroy(cmk_id)
            await self._audit(acct, "kms-system", "DestroyKey", cmk_id, "allow", "scheduled")
            key = await acct.store.get_key(cmk_id)
        return key

    def _require_admin(self, c: Caller) -> None:
        if not c.is_admin:
            raise _denied("not_admin")

    async def _admin_key(self, acct: _Account, c: Caller, cmk_id: str) -> KeyRow:
        self._require_admin(c)
        key = await self._load_key(acct, cmk_id)
        if key is None:
            raise KmsNotFoundError
        return key

    async def _material(self, acct: _Account, cmk_id: str, version: int) -> bytes:
        sealed = await acct.store.get_version(cmk_id, version)
        if sealed is None:
            raise KmsInvalidCiphertextError
        try:
            return crypto.open_material(acct.root, acct.info.account, cmk_id, version, sealed)
        except crypto.InvalidCiphertextError as exc:  # root key wrong / row tampered
            log.error("cmk_material_unreadable", cmk_id=cmk_id)
            raise KmsKeyUnavailableError from exc

    async def _authorize_crypto(self, acct: _Account, c: Caller, cmk_id: str,
                                action: CryptoAction, ctx: Mapping[str, str]) -> tuple[KeyRow, str]:
        key = await self._load_key(acct, cmk_id)
        if key is None:
            raise _denied("unknown_key")  # don't reveal existence
        decision = evaluate(KeyPolicy.model_validate_json(key.policy_json), c.principal,
                            action, ctx)
        if not decision.allowed:
            raise _denied(decision.reason)
        if key.state != KeyState.ENABLED:
            raise KmsKeyUnavailableError
        return key, decision.reason

    # --- management (account admin only) -------------------------------------------------

    async def create_key(self, c: Caller, description: str) -> str:
        async def op(acct: _Account) -> tuple[str, str]:
            self._require_admin(c)
            cmk_id = _CMK_RE_PREFIX + uuid.uuid4().hex
            sealed = crypto.seal_material(acct.root, acct.info.account, cmk_id, 1,
                                          crypto.new_key())
            await acct.store.insert_key(cmk_id, description, KeyPolicy().model_dump_json(),
                                        sealed, self._clock())
            return cmk_id, "admin"
        return await self._audited(c, "CreateKey", None, None, op)

    async def put_key_policy(self, c: Caller, cmk_id: str, policy: KeyPolicy) -> None:
        async def op(acct: _Account) -> tuple[None, str]:
            await self._admin_key(acct, c, cmk_id)
            await acct.store.set_policy(cmk_id, policy.model_dump_json())
            return None, "admin"
        await self._audited(c, "PutKeyPolicy", cmk_id, None, op)

    async def get_key_policy(self, c: Caller, cmk_id: str) -> KeyPolicy:
        async def op(acct: _Account) -> tuple[KeyPolicy, str]:
            key = await self._admin_key(acct, c, cmk_id)
            return KeyPolicy.model_validate_json(key.policy_json), "admin"
        return await self._audited(c, "GetKeyPolicy", cmk_id, None, op)

    async def describe_key(self, c: Caller, cmk_id: str) -> KeyRow:
        async def op(acct: _Account) -> tuple[KeyRow, str]:
            return await self._admin_key(acct, c, cmk_id), "admin"
        return await self._audited(c, "DescribeKey", cmk_id, None, op)

    async def rotate_key(self, c: Caller, cmk_id: str) -> int:
        async def op(acct: _Account) -> tuple[int, str]:
            async with acct.lock:
                key = await self._admin_key(acct, c, cmk_id)
                if key.state != KeyState.ENABLED:
                    raise KmsKeyUnavailableError
                v = key.current_version + 1
                sealed = crypto.seal_material(acct.root, acct.info.account, cmk_id, v,
                                              crypto.new_key())
                await acct.store.add_version(cmk_id, v, sealed, self._clock())
                return v, f"version:{v}"
        return await self._audited(c, "RotateKey", cmk_id, None, op)

    async def _set_state(self, c: Caller, op_name: str, cmk_id: str, frm: set[KeyState],
                         to: KeyState, deletion_date: float | None = None) -> None:
        async def op(acct: _Account) -> tuple[None, str]:
            async with acct.lock:
                key = await self._admin_key(acct, c, cmk_id)
                if key.state not in frm:
                    raise KmsKeyUnavailableError
                await acct.store.set_state(cmk_id, to, deletion_date)
                return None, f"state:{to.value}"
        await self._audited(c, op_name, cmk_id, None, op)

    async def disable_key(self, c: Caller, cmk_id: str) -> None:
        await self._set_state(c, "DisableKey", cmk_id, {KeyState.ENABLED, KeyState.DISABLED},
                              KeyState.DISABLED)

    async def enable_key(self, c: Caller, cmk_id: str) -> None:
        await self._set_state(c, "EnableKey", cmk_id, {KeyState.ENABLED, KeyState.DISABLED},
                              KeyState.ENABLED)

    async def schedule_key_deletion(self, c: Caller, cmk_id: str, pending_days: int) -> float:
        if not MIN_PENDING_DAYS <= pending_days <= MAX_PENDING_DAYS:
            raise KmsInvalidRequestError
        when = self._clock() + pending_days * 86_400
        await self._set_state(c, "ScheduleKeyDeletion", cmk_id,
                              {KeyState.ENABLED, KeyState.DISABLED},
                              KeyState.PENDING_DELETION, when)
        return when

    async def cancel_key_deletion(self, c: Caller, cmk_id: str) -> None:
        await self._set_state(c, "CancelKeyDeletion", cmk_id, {KeyState.PENDING_DELETION},
                              KeyState.DISABLED)

    async def list_audit(self, c: Caller, since_seq: int, limit: int) -> list[AuditEntry]:
        self._require_admin(c)
        acct = await self._get_acct(c)
        return await acct.store.list_audit(since_seq, min(max(limit, 1), 1000))

    async def verify_audit(self, c: Caller) -> tuple[bool, int]:
        self._require_admin(c)
        return await (await self._get_acct(c)).store.verify_audit()

    # --- crypto (key policy decides) ---------------------------------------------------

    @staticmethod
    def _ctx(ctx: Mapping[str, str]) -> dict[str, str]:
        try:
            return validate_context(ctx)
        except InvalidContextError as exc:
            raise KmsInvalidRequestError from exc

    async def generate_data_key(self, c: Caller, cmk_id: str,
                                ctx: Mapping[str, str]) -> DataKey:
        ctx = self._ctx(ctx)

        async def op(acct: _Account) -> tuple[DataKey, str]:
            key, reason = await self._authorize_crypto(acct, c, cmk_id,
                                                       CryptoAction.GENERATE_DATA_KEY, ctx)
            material = await self._material(acct, cmk_id, key.current_version)
            dek = crypto.new_key()
            header = crypto.BlobHeader(acct.info.account, cmk_id, key.current_version)
            blob = crypto.wrap_dek(material, header, canonical_context(ctx), dek)
            return DataKey(dek, blob, cmk_id, key.current_version), reason
        return await self._audited(c, "GenerateDataKey", cmk_id, ctx, op)

    async def _open_blob(self, acct: _Account, c: Caller, blob: bytes, action: CryptoAction,
                         ctx: dict[str, str]) -> tuple[bytes, crypto.BlobHeader, str]:
        try:
            header, header_bytes, body = crypto.parse_blob(blob)
        except crypto.InvalidCiphertextError as exc:
            raise KmsInvalidCiphertextError from exc
        if header.account != acct.info.account:
            raise _denied("foreign_account")
        _, reason = await self._authorize_crypto(acct, c, header.cmk_id, action, ctx)
        material = await self._material(acct, header.cmk_id, header.version)
        try:
            dek = crypto.unwrap_dek(material, header_bytes, body, canonical_context(ctx))
        except crypto.InvalidCiphertextError as exc:
            raise KmsInvalidCiphertextError from exc
        return dek, header, reason

    async def decrypt(self, c: Caller, blob: bytes,
                      ctx: Mapping[str, str]) -> tuple[bytes, str, int]:
        ctx = self._ctx(ctx)
        cmk_hint = _peek_cmk(blob)

        async def op(acct: _Account) -> tuple[tuple[bytes, str, int], str]:
            dek, header, reason = await self._open_blob(acct, c, blob, CryptoAction.DECRYPT,
                                                        ctx)
            return (dek, header.cmk_id, header.version), reason
        return await self._audited(c, "Decrypt", cmk_hint, ctx, op)

    async def re_encrypt(self, c: Caller, blob: bytes,
                         ctx: Mapping[str, str]) -> tuple[bytes, int]:
        """Re-wrap under the CMK's current version. The DEK never leaves the KMS."""
        ctx = self._ctx(ctx)
        cmk_hint = _peek_cmk(blob)

        async def op(acct: _Account) -> tuple[tuple[bytes, int], str]:
            dek, header, reason = await self._open_blob(acct, c, blob,
                                                        CryptoAction.RE_ENCRYPT, ctx)
            key = await acct.store.get_key(header.cmk_id)
            assert key is not None  # noqa: S101 - _open_blob authorized it
            material = await self._material(acct, header.cmk_id, key.current_version)
            new_header = crypto.BlobHeader(acct.info.account, header.cmk_id,
                                           key.current_version)
            new_blob = crypto.wrap_dek(material, new_header, canonical_context(ctx), dek)
            return (new_blob, key.current_version), reason
        return await self._audited(c, "ReEncrypt", cmk_hint, ctx, op)


def _denied(reason: str) -> KmsAccessDeniedError:
    exc = KmsAccessDeniedError()
    exc.audit_reason = reason  # type: ignore[attr-defined]
    return exc


def _peek_cmk(blob: bytes) -> str | None:
    try:
        return crypto.parse_blob(blob)[0].cmk_id
    except crypto.InvalidCiphertextError:
        return None

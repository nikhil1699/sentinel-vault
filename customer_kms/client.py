"""Async KMS client ("the SDK"). Signs every request. Used by our service and by
simulated customer admins.

Plaintext DEKs come back as ``bytearray`` so callers can zero them after use.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from customer_kms.policy import KeyPolicy
from customer_kms.protocol import b64d, b64e, sign_request


class KmsError(Exception):
    """Raised for any non-2xx KMS response. Carries only the KMS error code."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"KMS error {status} {code}")
        self.status = status
        self.code = code


@dataclass(slots=True)
class DataKey:
    plaintext: bytearray
    ciphertext_blob: bytes
    cmk_id: str
    cmk_version: int


class KmsClient:
    def __init__(self, http: httpx.AsyncClient, *, account: str, principal: str,
                 private_key: Ed25519PrivateKey, clock: Callable[[], float] = time.time) -> None:
        self._http = http
        self.account = account
        self.principal = principal
        self._key = private_key
        self._clock = clock

    async def call(self, op: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        path = f"/v1/{op}"
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = sign_request(self._key, method="POST", path=path, account=self.account,
                               principal=self.principal, body=body, now=self._clock())
        headers["content-type"] = "application/json"
        r = await self._http.post(path, content=body, headers=headers)
        if r.status_code >= 400:
            try:
                code = str(r.json()["error"]["code"])
            except (ValueError, KeyError, TypeError):
                code = "unknown"
            raise KmsError(r.status_code, code)
        data = r.json()
        assert isinstance(data, dict)  # noqa: S101
        return data

    # --- admin ---------------------------------------------------------------------

    async def create_key(self, description: str = "") -> str:
        return str((await self.call("CreateKey", {"description": description}))["cmk_id"])

    async def put_key_policy(self, cmk_id: str, policy: KeyPolicy) -> None:
        await self.call("PutKeyPolicy", {"cmk_id": cmk_id,
                                         "policy": policy.model_dump(mode="json")})

    async def get_key_policy(self, cmk_id: str) -> KeyPolicy:
        return KeyPolicy.model_validate(await self.call("GetKeyPolicy", {"cmk_id": cmk_id}))

    async def describe_key(self, cmk_id: str) -> dict[str, Any]:
        return await self.call("DescribeKey", {"cmk_id": cmk_id})

    async def rotate_key(self, cmk_id: str) -> int:
        return int((await self.call("RotateKey", {"cmk_id": cmk_id}))["cmk_version"])

    async def disable_key(self, cmk_id: str) -> None:
        await self.call("DisableKey", {"cmk_id": cmk_id})

    async def enable_key(self, cmk_id: str) -> None:
        await self.call("EnableKey", {"cmk_id": cmk_id})

    async def schedule_key_deletion(self, cmk_id: str, pending_days: int = 7) -> str:
        r = await self.call("ScheduleKeyDeletion", {"cmk_id": cmk_id,
                                                    "pending_days": pending_days})
        return str(r["deletion_date"])

    async def cancel_key_deletion(self, cmk_id: str) -> None:
        await self.call("CancelKeyDeletion", {"cmk_id": cmk_id})

    async def list_audit(self, since_seq: int = 0, limit: int = 1000) -> list[dict[str, Any]]:
        r = await self.call("ListAudit", {"since_seq": since_seq, "limit": limit})
        return list(r["entries"])

    async def verify_audit(self) -> bool:
        return bool((await self.call("VerifyAudit", {}))["intact"])

    # --- crypto --------------------------------------------------------------------

    async def generate_data_key(self, cmk_id: str, ctx: Mapping[str, str]) -> DataKey:
        r = await self.call("GenerateDataKey", {"cmk_id": cmk_id,
                                                "encryption_context": dict(ctx)})
        return DataKey(bytearray(b64d(r["plaintext"])), b64d(r["ciphertext_blob"]),
                       r["cmk_id"], int(r["cmk_version"]))

    async def decrypt(self, blob: bytes, ctx: Mapping[str, str]) -> bytearray:
        r = await self.call("Decrypt", {"ciphertext_blob": b64e(blob),
                                        "encryption_context": dict(ctx)})
        return bytearray(b64d(r["plaintext"]))

    async def re_encrypt(self, blob: bytes, ctx: Mapping[str, str]) -> tuple[bytes, int]:
        r = await self.call("ReEncrypt", {"ciphertext_blob": b64e(blob),
                                          "encryption_context": dict(ctx)})
        return b64d(r["ciphertext_blob"]), int(r["cmk_version"])

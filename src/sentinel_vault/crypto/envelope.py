"""Payload encryption with a data key: AES-256-GCM (``cryptography``), 96-bit random nonce.

AAD is canonical JSON of identifying fields. The keyring always adds ``tenant_id``,
``workspace_id``, ``dek_id`` and ``alg`` itself, so a caller can't forget to bind them.
Moving a ciphertext to another tenant, document, chunk, field or key fails to decrypt.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALG: Final = "A256GCM"
SCHEMA_VERSION: Final = 1
NONCE_BYTES: Final = 12
KEY_BYTES: Final = 32

AadValue = str | int


class DecryptionError(Exception):
    """Ciphertext, nonce or AAD doesn't authenticate. Treated as tampering."""


@dataclass(frozen=True, slots=True)
class Sealed:
    nonce: bytes
    ciphertext: bytes  # includes the 16-byte GCM tag


def canonical_aad(fields: Mapping[str, AadValue]) -> bytes:
    for k, v in fields.items():
        if not isinstance(k, str) or not isinstance(v, str | int) or isinstance(v, bool):
            raise TypeError("AAD fields must be str -> str|int")
    return json.dumps(dict(fields), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _check_key(key: bytes | bytearray) -> None:
    if len(key) != KEY_BYTES:
        raise ValueError("data key must be 32 bytes")


def seal(key: bytes | bytearray, plaintext: bytes, aad: bytes) -> Sealed:
    _check_key(key)
    nonce = os.urandom(NONCE_BYTES)
    return Sealed(nonce, AESGCM(key).encrypt(nonce, plaintext, aad))


def open_sealed(key: bytes | bytearray, sealed: Sealed, aad: bytes) -> bytes:
    _check_key(key)
    if len(sealed.nonce) != NONCE_BYTES:
        raise DecryptionError
    try:
        return AESGCM(key).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError from exc

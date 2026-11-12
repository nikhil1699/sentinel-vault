"""KMS-side cryptography. AES-256-GCM from ``cryptography``; nothing hand-rolled.

Two layers inside the KMS:

1. **Root key** (one per customer account, file 0600) seals each CMK version at rest.
2. **CMK version** wraps data keys (DEKs) for callers.

Wrapped-DEK blob layout (all big-endian)::

    magic "SVK1" (4) | acct_len (1) | account (n) | cmk_id (16) | version (4)
    | nonce (12) | ciphertext+tag (48)

AAD for the DEK wrap = header (everything before the nonce) + canonical encryption
context. So changing the account, CMK id, version, or context makes decryption fail.
"""

from __future__ import annotations

import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinel_vault.security.files import check_private, write_exclusive

KEY_BYTES: Final = 32
NONCE_BYTES: Final = 12
MAGIC: Final = b"SVK1"
_TAG_BYTES: Final = 16


class InvalidCiphertextError(Exception):
    """Any blob that fails to parse or authenticate. One error type, no detail."""


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def load_or_create_root_key(path: Path) -> bytes:
    if path.exists():
        check_private(path)
        key = path.read_bytes()
        if len(key) != KEY_BYTES:
            raise ValueError(f"{path} is not a {KEY_BYTES}-byte key")
        return key
    key = new_key()
    write_exclusive(path, key, 0o600)
    return key


def _material_aad(account: str, cmk_id: str, version: int) -> bytes:
    return f"cmk-material|{account}|{cmk_id}|{version}".encode("ascii")


def seal_material(root: bytes, account: str, cmk_id: str, version: int,
                  material: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(root).encrypt(nonce, material,
                                        _material_aad(account, cmk_id, version))


def open_material(root: bytes, account: str, cmk_id: str, version: int,
                  sealed: bytes) -> bytes:
    try:
        return AESGCM(root).decrypt(sealed[:NONCE_BYTES], sealed[NONCE_BYTES:],
                                    _material_aad(account, cmk_id, version))
    except InvalidTag as exc:  # root key wrong or DB row tampered
        raise InvalidCiphertextError from exc


@dataclass(frozen=True, slots=True)
class BlobHeader:
    account: str
    cmk_id: str  # "cmk_<32 hex>"
    version: int

    def encode(self) -> bytes:
        acct = self.account.encode("ascii")
        return (MAGIC + struct.pack(">B", len(acct)) + acct
                + uuid.UUID(hex=self.cmk_id.removeprefix("cmk_")).bytes
                + struct.pack(">I", self.version))


def parse_blob(blob: bytes) -> tuple[BlobHeader, bytes, bytes]:
    """Returns (header, header_bytes, nonce+ciphertext). Strict length checks."""
    try:
        if blob[:4] != MAGIC:
            raise ValueError
        n = blob[4]
        acct = blob[5:5 + n].decode("ascii")
        off = 5 + n
        cmk = "cmk_" + uuid.UUID(bytes=blob[off:off + 16]).hex
        (version,) = struct.unpack(">I", blob[off + 16:off + 20])
        header_len = off + 20
        rest = blob[header_len:]
        if len(rest) != NONCE_BYTES + KEY_BYTES + _TAG_BYTES or version < 1:
            raise ValueError
        return BlobHeader(acct, cmk, version), blob[:header_len], rest
    except (ValueError, IndexError, UnicodeDecodeError, struct.error) as exc:
        raise InvalidCiphertextError from exc


def wrap_dek(material: bytes, header: BlobHeader, ctx_bytes: bytes, dek: bytes) -> bytes:
    hdr = header.encode()
    nonce = os.urandom(NONCE_BYTES)
    return hdr + nonce + AESGCM(material).encrypt(nonce, dek, hdr + ctx_bytes)


def unwrap_dek(material: bytes, header_bytes: bytes, body: bytes, ctx_bytes: bytes) -> bytes:
    try:
        return AESGCM(material).decrypt(body[:NONCE_BYTES], body[NONCE_BYTES:],
                                        header_bytes + ctx_bytes)
    except InvalidTag as exc:
        raise InvalidCiphertextError from exc

"""Customer KMS wire protocol: request signing and encryption context.

This is the "published SDK" part of the KMS. Both the KMS server and any client
(our service, customer admins) use it, the way AWS SDKs share SigV4.

Signature (Ed25519) covers::

    KMS1 \\n METHOD \\n PATH \\n ACCOUNT \\n PRINCIPAL \\n UNIX_TIME \\n NONCE \\n SHA256(BODY)

The server rejects a bad signature, a clock skew over 60 s, or a reused nonce.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from collections.abc import Mapping
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

VERSION: Final = "KMS1"
H_ACCOUNT: Final = "x-kms-account"
H_PRINCIPAL: Final = "x-kms-principal"
H_DATE: Final = "x-kms-date"
H_NONCE: Final = "x-kms-nonce"
H_SIGNATURE: Final = "x-kms-signature"
MAX_SKEW_SECONDS: Final = 60

NAME_RE: Final = re.compile(r"[a-z][a-z0-9-]{1,62}")
NONCE_RE: Final = re.compile(r"[0-9a-f]{32}")
_CTX_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")
_CTX_VAL_RE: Final = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
MAX_CONTEXT_ENTRIES: Final = 10


class InvalidContextError(ValueError):
    pass


def validate_context(ctx: Mapping[str, str]) -> dict[str, str]:
    """Encryption context: small, ASCII, non-secret identifiers only (it is logged/audited)."""
    if len(ctx) > MAX_CONTEXT_ENTRIES:
        raise InvalidContextError("too many encryption context entries")
    out: dict[str, str] = {}
    for k, v in ctx.items():
        if not (isinstance(k, str) and _CTX_KEY_RE.fullmatch(k)):
            raise InvalidContextError("invalid encryption context key")
        if not (isinstance(v, str) and _CTX_VAL_RE.fullmatch(v)):
            raise InvalidContextError("invalid encryption context value")
        out[k] = v
    return out


def canonical_context(ctx: Mapping[str, str]) -> bytes:
    return json.dumps(dict(ctx), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def canonical_request(method: str, path: str, account: str, principal: str, date: str,
                      nonce: str, body: bytes) -> bytes:
    return "\n".join([VERSION, method.upper(), path, account, principal, date, nonce,
                      hashlib.sha256(body).hexdigest()]).encode("ascii")


def sign_request(key: Ed25519PrivateKey, *, method: str, path: str, account: str,
                 principal: str, body: bytes, now: float,
                 nonce: str | None = None) -> dict[str, str]:
    date = str(int(now))
    nonce = nonce or secrets.token_hex(16)
    sig = key.sign(canonical_request(method, path, account, principal, date, nonce, body))
    return {H_ACCOUNT: account, H_PRINCIPAL: principal, H_DATE: date, H_NONCE: nonce,
            H_SIGNATURE: base64.b64encode(sig).decode("ascii")}


def verify_signature(pub: Ed25519PublicKey, signature_b64: str, *, method: str, path: str,
                     account: str, principal: str, date: str, nonce: str,
                     body: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        sig = base64.b64decode(signature_b64, validate=True)
        pub.verify(sig, canonical_request(method, path, account, principal, date, nonce, body))
    except (InvalidSignature, ValueError):
        return False
    return True


def b64e(data: bytes | bytearray) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)

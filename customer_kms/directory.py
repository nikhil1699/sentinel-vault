"""Identity directory for the simulated KMS (stands in for AWS IAM / account identity).

Layout under the KMS data dir::

    principals.json                     external principals: name -> Ed25519 public key
    accounts/<account>/account.json     account admin identity
    accounts/<account>/root.key         account root key (0600), seals CMKs at rest
    accounts/<account>/kms.db           keys, versions, nonces, audit log

Each customer account is its own folder with its own root key and DB: one account's
compromise or deletion never touches another's.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from customer_kms.protocol import NAME_RE
from sentinel_vault.security.files import ensure_private_dir, write_exclusive

ADMIN_SUFFIX = "-admin"


class DirectoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AccountInfo:
    account: str
    admin_principal: str
    admin_public_key: Ed25519PublicKey
    path: Path


def _load_pub(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise DirectoryError("public key must be Ed25519")
    return key


def _pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def account_dir(data_dir: Path, account: str) -> Path:
    if not NAME_RE.fullmatch(account):
        raise DirectoryError("invalid account name")
    return data_dir / "accounts" / account


def create_account(data_dir: Path, account: str, admin_public_pem: str) -> AccountInfo:
    path = account_dir(data_dir, account)
    if path.exists():
        raise DirectoryError(f"account {account} already exists")
    pub = _load_pub(admin_public_pem)
    ensure_private_dir(path)
    info = {"account": account, "admin_principal": account + ADMIN_SUFFIX,
            "admin_public_key": _pem(pub), "created_at": time.time()}
    write_exclusive(path / "account.json", json.dumps(info, indent=2).encode(), 0o600)
    return AccountInfo(account, account + ADMIN_SUFFIX, pub, path)


def load_account(data_dir: Path, account: str) -> AccountInfo | None:
    try:
        path = account_dir(data_dir, account)
    except DirectoryError:
        return None
    f = path / "account.json"
    if not f.is_file():
        return None
    raw = json.loads(f.read_text())
    return AccountInfo(raw["account"], raw["admin_principal"],
                       _load_pub(raw["admin_public_key"]), path)


def _principals_file(data_dir: Path) -> Path:
    return data_dir / "principals.json"


def _read_principals(data_dir: Path) -> dict[str, str]:
    f = _principals_file(data_dir)
    return dict(json.loads(f.read_text())) if f.is_file() else {}


def register_principal(data_dir: Path, name: str, public_pem: str,
                       replace: bool = False) -> bool:
    """Register an external principal (e.g. our service). Returns True if changed."""
    if not NAME_RE.fullmatch(name) or name.endswith(ADMIN_SUFFIX):
        raise DirectoryError("invalid principal name")
    pem = _pem(_load_pub(public_pem))
    ensure_private_dir(data_dir)
    current = _read_principals(data_dir)
    if current.get(name) == pem:
        return False
    if name in current and not replace:
        raise DirectoryError(f"principal {name} already registered with a different key")
    current[name] = pem
    write_exclusive(_principals_file(data_dir), json.dumps(current, indent=2).encode(), 0o600)
    return True


def load_principal(data_dir: Path, name: str) -> Ed25519PublicKey | None:
    pem = _read_principals(data_dir).get(name)
    return None if pem is None else _load_pub(pem)

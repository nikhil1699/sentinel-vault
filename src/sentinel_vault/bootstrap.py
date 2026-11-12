"""First-run setup: private directories and the service signing key.

Idempotent. Never overwrites an existing key. Refuses to use a key or directory
that other users can read (same rule as OpenSSH).

Run: ``python -m sentinel_vault.bootstrap``
"""

from __future__ import annotations

import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_vault.config import Settings
from sentinel_vault.security.files import (
    InsecurePermissionsError,
    check_private,
    ensure_private_dir,
    write_exclusive,
)

__all__ = ["InsecurePermissionsError", "bootstrap", "ensure_private_dir", "ensure_service_keypair"]

def ensure_service_keypair(settings: Settings) -> bool:
    """Create the Ed25519 key our service signs KMS requests with.

    Returns True if a new key was created, False if a valid one already existed.
    """
    ensure_private_dir(settings.secrets_dir)
    priv_path = settings.service_private_key_path
    if priv_path.exists():
        check_private(priv_path)
        key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{priv_path} is not an Ed25519 private key")
        return False

    key = Ed25519PrivateKey.generate()
    write_exclusive(
        priv_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    write_exclusive(
        settings.service_public_key_path,
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        0o644,
    )
    return True


def bootstrap(settings: Settings) -> list[str]:
    """Run every first-run step. Returns human-readable status lines."""
    lines: list[str] = []
    ensure_private_dir(settings.data_dir)
    lines.append(f"data dir {settings.data_dir}")
    created = ensure_service_keypair(settings)
    lines.append(f"service signing key {'created' if created else 'present'}")
    return lines


def main() -> int:
    try:
        for line in bootstrap(Settings()):
            print(f"[ok]   {line}")
    except (InsecurePermissionsError, ValueError) as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

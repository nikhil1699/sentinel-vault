"""First-run setup: private directories and the service signing key.

Idempotent. Never overwrites an existing key. Refuses to use a key or directory
that other users can read (same rule as OpenSSH).

Run: ``python -m sentinel_vault.bootstrap``
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_vault.config import Settings

_GROUP_OTHER_BITS = stat.S_IRWXG | stat.S_IRWXO


class InsecurePermissionsError(RuntimeError):
    """A secret file or directory is readable by group or others."""


def _check_private(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & _GROUP_OTHER_BITS:
        raise InsecurePermissionsError(
            f"{path} is accessible by group/others (mode {stat.S_IMODE(mode):o}); "
            f"fix with: chmod {'700' if path.is_dir() else '600'} {path}"
        )


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` with mode 0700, or verify an existing one is private."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_private(path)
    return path


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    """Write via a temp file created with O_EXCL, then atomically rename into place."""
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def ensure_service_keypair(settings: Settings) -> bool:
    """Create the Ed25519 key our service signs KMS requests with.

    Returns True if a new key was created, False if a valid one already existed.
    """
    ensure_private_dir(settings.secrets_dir)
    priv_path = settings.service_private_key_path
    if priv_path.exists():
        _check_private(priv_path)
        key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{priv_path} is not an Ed25519 private key")
        return False

    key = Ed25519PrivateKey.generate()
    _write_exclusive(
        priv_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    _write_exclusive(
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

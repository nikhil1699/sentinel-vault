"""KMS operator CLI (simulates the cloud provider's account signup and IAM).

    python -m customer_kms.cli register-principal sentinel-svc .secrets/service_ed25519.pub.pem
    python -m customer_kms.cli create-account acme --admin-key-out .secrets/customers/acme/admin.pem
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from customer_kms.config import KmsSettings
from customer_kms.directory import DirectoryError, create_account, register_principal
from sentinel_vault.security.files import (
    InsecurePermissionsError,
    ensure_private_dir,
    write_exclusive,
)


def new_admin_key(out: Path) -> str:
    """Create a customer admin key pair. Private key to ``out`` (0600). Returns public PEM."""
    ensure_private_dir(out.parent)
    key = Ed25519PrivateKey.generate()
    write_exclusive(out, key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()), 0o600)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="customer_kms.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("register-principal")
    rp.add_argument("name")
    rp.add_argument("public_key", type=Path)
    rp.add_argument("--replace", action="store_true")
    ca = sub.add_parser("create-account")
    ca.add_argument("account")
    ca.add_argument("--admin-key-out", type=Path, required=True)
    args = p.parse_args(argv)
    data_dir = KmsSettings().data_dir
    try:
        ensure_private_dir(data_dir)
        if args.cmd == "register-principal":
            changed = register_principal(data_dir, args.name, args.public_key.read_text(),
                                         args.replace)
            print(f"[ok]   KMS principal {args.name} {'registered' if changed else 'present'}")
        else:
            if args.admin_key_out.exists():
                raise DirectoryError(f"{args.admin_key_out} already exists")
            create_account(data_dir, args.account, new_admin_key(args.admin_key_out))
            print(f"[ok]   KMS account {args.account} created")
    except (DirectoryError, InsecurePermissionsError, OSError) as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

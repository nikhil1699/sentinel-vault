"""Small helpers for trying the API by hand (see docs/TRY-IT-YOURSELF.md).

Our API is plain HTTP + JSON, so ``curl`` covers it. Two things are not curl-able, and
this CLI does them:

- **Creating a customer** — onboarding happens on the customer's side (KMS account,
  master key, key policy) and on our operator side (tenant + users). No public signup API.
- **Customer key actions** (rotate, disable, …) — the customer's KMS requires
  Ed25519-signed requests, made here with the customer's admin key from ``.secrets/``.

    ./run.sh customer new <tenant>
    ./run.sh customer rotate|disable|enable|describe|audit <tenant>
    ./run.sh password <tenant> <user>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from customer_kms.client import KmsError
from reviewer_kit.common import USERS, Stack, live_stack, load_customer, provision_customer
from reviewer_kit.ui import fail, ok
from sentinel_vault.domain.ids import TenantId

KEY_ACTIONS = ("rotate", "disable", "enable", "describe", "audit")


async def new_customer(stack: Stack, tenant: str) -> str:
    TenantId(tenant)  # validate early: lowercase, 3–32 chars
    if load_customer(stack, tenant) is not None:
        return fail(f"customer {tenant} already exists")
    c = await provision_customer(stack, tenant)
    lines = [ok(f"customer {tenant} onboarded (BYOK probe passed)"),
             f"       master key (in the customer's vault): {c.cmk_id}",
             f"       users: {', '.join(f'{u} ({len(USERS[u])} scopes)' for u in USERS)}",
             f"       passwords: ./run.sh password {tenant} <user>"]
    return "\n".join(lines)


async def key_action(stack: Stack, action: str, tenant: str) -> str:
    c = load_customer(stack, tenant)
    if c is None:
        return fail(f"no customer {tenant} in .secrets/customers/ "
                    "(seeded tenants and ones made with './run.sh customer new' work)")
    kms = c.kms_admin(stack)
    try:
        if action == "rotate":
            return ok(f"{tenant}: master key rotated to v{await kms.rotate_key(c.cmk_id)} "
                      "— now call POST /tenant/keys/rewrap")
        if action == "disable":
            await kms.disable_key(c.cmk_id)
            return ok(f"{tenant}: master key DISABLED — call POST /tenant/cache/flush to make "
                      "it bite now, then try reading a document")
        if action == "enable":
            await kms.enable_key(c.cmk_id)
            return ok(f"{tenant}: master key enabled again")
        if action == "describe":
            return json.dumps(await kms.describe_key(c.cmk_id), indent=2)
        entries = await kms.list_audit()
        rows = [f"{e['seq']:>4}  {e['operation']:<16} {e['principal']:<26} {e['outcome']:<5} "
                f"{e['reason']:<22} tenant_id={e['encryption_context'].get('tenant_id', '-')}"
                for e in entries[-25:]]
        intact = await kms.verify_audit()
        return "\n".join([*rows, ok(f"{len(entries)} entries, hash chain "
                                     f"{'intact' if intact else 'BROKEN'}")])
    except KmsError as exc:
        return fail(f"KMS refused: {exc.code}")


def password(stack: Stack, tenant: str, user: str) -> str | None:
    c = load_customer(stack, tenant)
    return None if c is None else c.passwords.get(user)


async def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="run.sh")
    sub = p.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("customer")
    cu.add_argument("action", choices=("new", *KEY_ACTIONS))
    cu.add_argument("tenant")
    pw = sub.add_parser("password")
    pw.add_argument("tenant")
    pw.add_argument("user", choices=tuple(USERS))
    a = p.parse_args(argv)
    async with live_stack() as stack:
        if a.cmd == "password":
            value = password(stack, a.tenant, a.user)
            if value is None:
                print(fail(f"no customer {a.tenant}"), file=sys.stderr)
                return 1
            print(value)
            return 0
        try:
            msg = (await new_customer(stack, a.tenant) if a.action == "new"
                   else await key_action(stack, a.action, a.tenant))
        except ValueError:
            msg = fail("tenant names are lowercase letters, digits and '-', 3–32 chars")
    print(msg)
    return 1 if msg.lstrip().startswith(("[fail]", "\033[1;31m")) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

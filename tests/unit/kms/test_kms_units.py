"""Unit tests: KMS protocol, policy engine, blob crypto, directory."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from customer_kms import crypto
from customer_kms.directory import (
    DirectoryError,
    create_account,
    load_account,
    load_principal,
    register_principal,
)
from customer_kms.policy import CryptoAction, KeyPolicy, Statement, evaluate
from customer_kms.protocol import (
    H_DATE,
    H_NONCE,
    H_SIGNATURE,
    InvalidContextError,
    canonical_context,
    sign_request,
    validate_context,
    verify_signature,
)
from sentinel_vault.security.files import InsecurePermissionsError
from tests.kms_env import pub_pem, tenant_policy

# --- protocol ----------------------------------------------------------------------------


def _sign(key: Ed25519PrivateKey, body: bytes = b"{}") -> dict[str, str]:
    return sign_request(key, method="POST", path="/v1/Decrypt", account="acme",
                        principal="sentinel-svc", body=body, now=1000.0)


def _verify(key: Ed25519PrivateKey, h: dict[str, str], body: bytes = b"{}",
            path: str = "/v1/Decrypt", account: str = "acme") -> bool:
    return verify_signature(key.public_key(), h[H_SIGNATURE], method="POST", path=path,
                            account=account, principal="sentinel-svc", date=h[H_DATE],
                            nonce=h[H_NONCE], body=body)


def test_signature_roundtrip_and_binding() -> None:
    k = Ed25519PrivateKey.generate()
    h = _sign(k)
    assert _verify(k, h)
    assert not _verify(k, h, body=b'{"x":1}')            # body tampered
    assert not _verify(k, h, path="/v1/GenerateDataKey")  # different operation
    assert not _verify(k, h, account="beta")             # different account
    assert not _verify(Ed25519PrivateKey.generate(), h)  # different key
    assert not _verify(k, {**h, H_SIGNATURE: "!!notbase64"})


def test_nonces_are_unique() -> None:
    k = Ed25519PrivateKey.generate()
    assert len({_sign(k)[H_NONCE] for _ in range(200)}) == 200


def test_context_canonical_is_order_independent() -> None:
    assert canonical_context({"b": "2", "a": "1"}) == canonical_context({"a": "1", "b": "2"})
    assert canonical_context({"a": "1"}) == b'{"a":"1"}'


@pytest.mark.parametrize("bad", [
    {"Tenant": "x"}, {"t": ""}, {"t": "a b"}, {"t": "x" * 200}, {"t": "café"},
    {f"k{i}": "v" for i in range(11)}, {"t": 5},
])
def test_context_validation(bad: dict[str, object]) -> None:
    with pytest.raises(InvalidContextError):
        validate_context(bad)  # type: ignore[arg-type]


# --- policy ------------------------------------------------------------------------------


def test_policy_allow_with_matching_context() -> None:
    p = tenant_policy("acme")
    d = evaluate(p, "sentinel-svc", CryptoAction.DECRYPT,
                 {"tenant_id": "acme", "purpose": "vector"})
    assert d.allowed and d.reason == "allow:AllowSentinel"


@pytest.mark.parametrize(("principal", "ctx", "reason"), [
    ("sentinel-svc", {"tenant_id": "beta", "purpose": "vector"}, "implicit_deny"),
    ("sentinel-svc", {"tenant_id": "acme"}, "implicit_deny"),  # required key missing
    ("sentinel-svc", {}, "implicit_deny"),
    ("evil-svc", {"tenant_id": "acme", "purpose": "vector"}, "implicit_deny"),
])
def test_policy_denies(principal: str, ctx: dict[str, str], reason: str) -> None:
    d = evaluate(tenant_policy("acme"), principal, CryptoAction.DECRYPT, ctx)
    assert not d.allowed and d.reason == reason


def test_explicit_deny_wins() -> None:
    p = KeyPolicy(statements=[
        *tenant_policy("acme").statements,
        Statement(sid="NoVault", effect="Deny", principals=["sentinel-svc"],
                  actions=[CryptoAction.DECRYPT],
                  condition={"encryption_context_equals": {"purpose": "vault"}}),  # type: ignore[arg-type]
    ])
    allowed = {"tenant_id": "acme", "purpose": "vector"}
    denied = {"tenant_id": "acme", "purpose": "vault"}
    assert evaluate(p, "sentinel-svc", CryptoAction.DECRYPT, allowed).allowed
    d = evaluate(p, "sentinel-svc", CryptoAction.DECRYPT, denied)
    assert not d.allowed and d.reason == "deny:NoVault"


def test_action_scoping() -> None:
    p = tenant_policy("acme", actions=[CryptoAction.DECRYPT])
    c = {"tenant_id": "acme", "purpose": "vector"}
    assert not evaluate(p, "sentinel-svc", CryptoAction.GENERATE_DATA_KEY, c).allowed


def test_empty_policy_denies_everything() -> None:
    assert not evaluate(KeyPolicy(), "sentinel-svc", CryptoAction.DECRYPT, {}).allowed


@pytest.mark.parametrize("bad", [
    {"statements": [{"sid": "a", "effect": "Allow", "principals": ["*"],
                     "actions": ["Decrypt"]}]},
    {"statements": [{"sid": "a", "effect": "Allow", "principals": ["svc"],
                     "actions": ["CreateKey"]}]},          # admin ops not grantable
    {"statements": [{"sid": "a", "effect": "Allow", "principals": [],
                     "actions": ["Decrypt"]}]},
    {"statements": [{"sid": "a", "effect": "Maybe", "principals": ["svc"],
                     "actions": ["Decrypt"]}]},
    {"statements": [], "extra": 1},
    {"version": "2012-10-17", "statements": []},
])
def test_policy_schema_rejects(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        KeyPolicy.model_validate(bad)


# --- blob crypto ----------------------------------------------------------------------------

CMK = "cmk_" + "ab" * 16


def _blob(ctx: bytes = b'{"t":"a"}') -> tuple[bytes, bytes, bytes]:
    material, dek = crypto.new_key(), crypto.new_key()
    blob = crypto.wrap_dek(material, crypto.BlobHeader("acme", CMK, 3), ctx, dek)
    return material, dek, blob


def test_blob_roundtrip_and_header() -> None:
    material, dek, blob = _blob()
    header, hb, body = crypto.parse_blob(blob)
    assert (header.account, header.cmk_id, header.version) == ("acme", CMK, 3)
    assert crypto.unwrap_dek(material, hb, body, b'{"t":"a"}') == dek
    assert dek not in blob


def test_blob_wrong_context_fails() -> None:
    material, _, blob = _blob()
    _, hb, body = crypto.parse_blob(blob)
    with pytest.raises(crypto.InvalidCiphertextError):
        crypto.unwrap_dek(material, hb, body, b'{"t":"b"}')


@pytest.mark.parametrize("pos", list(range(0, 90, 7)))
def test_any_bit_flip_detected(pos: int) -> None:
    material, _, blob = _blob()
    tampered = bytearray(blob)
    tampered[pos % len(blob)] ^= 0x01
    with pytest.raises(crypto.InvalidCiphertextError):
        h, hb, body = crypto.parse_blob(bytes(tampered))
        crypto.unwrap_dek(material, hb, body, b'{"t":"a"}')


def test_header_swap_detected() -> None:
    """Rewrite the version/account in the header: AAD mismatch."""
    material, _, blob = _blob()
    _, hb, body = crypto.parse_blob(blob)
    forged = crypto.BlobHeader("acme", CMK, 1).encode()
    with pytest.raises(crypto.InvalidCiphertextError):
        crypto.unwrap_dek(material, forged, body, b'{"t":"a"}')


@pytest.mark.parametrize("junk", [b"", b"SVK1", b"XXXX" + b"\x00" * 80, os.urandom(85),
                                  b"SVK1\x04acme" + b"\x00" * 16 + b"\x00\x00\x00\x00"
                                  + b"\x00" * 60])
def test_parse_rejects_junk(junk: bytes) -> None:
    with pytest.raises(crypto.InvalidCiphertextError):
        crypto.parse_blob(junk)


def test_material_sealing() -> None:
    root, m = crypto.new_key(), crypto.new_key()
    sealed = crypto.seal_material(root, "acme", CMK, 1, m)
    assert crypto.open_material(root, "acme", CMK, 1, sealed) == m
    for args in [("beta", CMK, 1), ("acme", CMK, 2), ("acme", "cmk_" + "cd" * 16, 1)]:
        with pytest.raises(crypto.InvalidCiphertextError):
            crypto.open_material(root, *args, sealed)
    with pytest.raises(crypto.InvalidCiphertextError):
        crypto.open_material(crypto.new_key(), "acme", CMK, 1, sealed)


def test_root_key_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    p = tmp_path / "root.key"
    k = crypto.load_or_create_root_key(p)
    assert crypto.load_or_create_root_key(p) == k
    p.chmod(0o644)
    with pytest.raises(InsecurePermissionsError):
        crypto.load_or_create_root_key(p)
    p.chmod(0o600)
    p.write_bytes(b"short")
    with pytest.raises(ValueError):
        crypto.load_or_create_root_key(p)


# --- directory ------------------------------------------------------------------------------


def test_directory(tmp_path: Path) -> None:
    d = tmp_path / "kms"
    k = Ed25519PrivateKey.generate()
    assert register_principal(d, "sentinel-svc", pub_pem(k)) is True
    assert register_principal(d, "sentinel-svc", pub_pem(k)) is False  # idempotent
    with pytest.raises(DirectoryError):
        register_principal(d, "sentinel-svc", pub_pem(Ed25519PrivateKey.generate()))
    assert register_principal(d, "sentinel-svc", pub_pem(Ed25519PrivateKey.generate()),
                              replace=True)
    with pytest.raises(DirectoryError):  # can't impersonate an account admin
        register_principal(d, "acme-admin", pub_pem(k))
    with pytest.raises(DirectoryError):
        register_principal(d, "../evil", pub_pem(k))
    assert load_principal(d, "nobody") is None

    info = create_account(d, "acme", pub_pem(k))
    assert info.admin_principal == "acme-admin"
    assert load_account(d, "acme") is not None
    assert load_account(d, "../acme") is None
    assert load_account(d, "zeta") is None
    with pytest.raises(DirectoryError):
        create_account(d, "acme", pub_pem(k))

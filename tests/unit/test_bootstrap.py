from __future__ import annotations

import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_vault import bootstrap as bs
from sentinel_vault.config import Settings


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_creates_private_dirs_and_key(settings: Settings) -> None:
    lines = bs.bootstrap(settings)
    assert any("created" in line for line in lines)
    assert _mode(settings.secrets_dir) == 0o700
    assert _mode(settings.data_dir) == 0o700
    assert _mode(settings.service_private_key_path) == 0o600
    key = serialization.load_pem_private_key(
        settings.service_private_key_path.read_bytes(), password=None
    )
    assert isinstance(key, Ed25519PrivateKey)
    pub = serialization.load_pem_public_key(settings.service_public_key_path.read_bytes())
    assert pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def test_idempotent_never_overwrites_key(settings: Settings) -> None:
    bs.bootstrap(settings)
    first = settings.service_private_key_path.read_bytes()
    lines = bs.bootstrap(settings)
    assert any("present" in line for line in lines)
    assert settings.service_private_key_path.read_bytes() == first
    assert not list(settings.secrets_dir.glob(".*.tmp"))


def test_refuses_world_readable_key(settings: Settings) -> None:
    bs.bootstrap(settings)
    settings.service_private_key_path.chmod(0o644)
    with pytest.raises(bs.InsecurePermissionsError, match="chmod 600"):
        bs.bootstrap(settings)


def test_refuses_group_readable_secrets_dir(settings: Settings) -> None:
    settings.secrets_dir.mkdir(mode=0o750, parents=True)
    settings.secrets_dir.chmod(0o750)
    with pytest.raises(bs.InsecurePermissionsError, match="chmod 700"):
        bs.bootstrap(settings)


def test_refuses_non_ed25519_key(settings: Settings) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    bs.ensure_private_dir(settings.secrets_dir)
    other = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    settings.service_private_key_path.write_bytes(other)
    settings.service_private_key_path.chmod(0o600)
    with pytest.raises(ValueError, match="not an Ed25519"):
        bs.ensure_service_keypair(settings)


def test_main_reports_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                              capsys: pytest.CaptureFixture[str]) -> None:
    secrets = tmp_path / "s"
    secrets.mkdir(mode=0o755)
    secrets.chmod(0o755)
    monkeypatch.setenv("SV_SECRETS_DIR", str(secrets))
    monkeypatch.setenv("SV_DATA_DIR", str(tmp_path / "d"))
    assert bs.main() == 1
    assert "[fail]" in capsys.readouterr().err


def test_main_ok(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                 capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("SV_SECRETS_DIR", str(tmp_path / "s"))
    monkeypatch.setenv("SV_DATA_DIR", str(tmp_path / "d"))
    assert bs.main() == 0
    assert "[ok]" in capsys.readouterr().out

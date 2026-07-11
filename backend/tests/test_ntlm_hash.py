"""Tests fuer den NTLM-Hash-Generator -- inklusive Verifikation der
selbst geschriebenen MD4-Implementierung gegen die offiziellen
RFC-1320-Testvektoren (MD4 fehlt in modernen OpenSSL-3.x-Umgebungen per
Default, daher eine eigene, reine Python-Implementierung statt einer
Fremdabhaengigkeit).
"""

import pytest
from pydantic import ValidationError

from app.modules.utilities.ntlm_hash import NtlmHashGeneratorModule, _md4, ntlm_hash


# --- MD4-Kernimplementierung gegen RFC 1320 --------------------------------

@pytest.mark.parametrize("input_bytes,expected_hex", [
    (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    (b"message digest", "d9130a8164549fe818874806e1c7014b"),
    (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
    (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"),
])
def test_md4_matches_official_rfc1320_test_vectors(input_bytes, expected_hex):
    assert _md4(input_bytes).hex() == expected_hex


def test_ntlm_hash_matches_known_public_test_vector():
    assert ntlm_hash("password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_ntlm_hash_empty_password():
    # NTLM-Hash eines leeren Passworts ist ein weiterer oeffentlich
    # dokumentierter Referenzwert.
    assert ntlm_hash("") == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_ntlm_hash_is_case_sensitive_and_deterministic():
    assert ntlm_hash("Password123") != ntlm_hash("password123")
    assert ntlm_hash("SameInput") == ntlm_hash("SameInput")


# --- Modul-Ebene -------------------------------------------------------------

def test_ntlm_module_registered():
    from app.modules import get_registry

    assert "ntlm-hash-generator" in get_registry()


def test_ntlm_module_is_redacted_from_history():
    assert NtlmHashGeneratorModule.redact_input_in_history is True


def test_ntlm_input_rejects_too_long_password():
    with pytest.raises(ValidationError):
        NtlmHashGeneratorModule.Input(password="x" * 2000)


@pytest.mark.asyncio
async def test_ntlm_module_run_produces_correct_hash():
    result = await NtlmHashGeneratorModule().run(NtlmHashGeneratorModule.Input(password="password"))
    assert result.ntlm_hash == "8846f7eaee8fb117ad06bdd830b7586c"


def test_ntlm_password_not_persisted_in_history(client):
    import pyotp
    from tests.conftest import create_admin as _create_admin

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    client.post("/api/v1/tools/ntlm-hash-generator", json={"password": "mein-geheimes-testpasswort"})

    from app.core.db import SessionLocal
    from app.models.user import ToolExecution

    db = SessionLocal()
    execution = db.query(ToolExecution).filter_by(tool_slug="ntlm-hash-generator").first()
    db.close()
    assert execution is not None
    assert "mein-geheimes-testpasswort" not in (execution.input_json or "")
    assert "redacted" in execution.input_json

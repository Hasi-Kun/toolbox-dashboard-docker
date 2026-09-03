"""Tests fuer den DKIM Validator (vollstaendige kryptografische
Signaturpruefung). Nutzt ECHTE, per dkimpy selbst signierte
Testnachrichten mit einem frisch generierten RSA-Schluesselpaar --
der DNS-Lookup wird gemockt (simuliert den veroeffentlichten
TXT-Record), die eigentliche Kryptoverifikation laeuft komplett echt.
"""

from unittest.mock import patch

import dkim
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.modules.mail.dkim_validator import DkimValidatorModule
from tests.conftest import create_admin as _create_admin


def _generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    import base64

    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_der).decode()
    return private_pem, public_key_b64


def _sign_test_message(private_pem: bytes, body_text: str = "Testnachricht.") -> bytes:
    message = (
        b"From: absender@test-domain.example\r\n"
        b"To: empfaenger@example.com\r\n"
        b"Subject: Testnachricht\r\n"
        b"Date: Mon, 1 Sep 2026 12:00:00 +0000\r\n"
        b"\r\n" + body_text.encode() + b"\r\n"
    )
    signature = dkim.sign(
        message=message, selector=b"testselector", domain=b"test-domain.example",
        privkey=private_pem, include_headers=[b"from", b"to", b"subject", b"date"],
    )
    return signature + message


def _patched_verify_with_key(public_key_b64: str):
    def fake_dnsfunc(name, timeout=5):
        return f"v=DKIM1; k=rsa; p={public_key_b64}"

    original_verify = dkim.DKIM.verify

    def patched(self, idx=0, dnsfunc=None):
        return original_verify(self, idx=idx, dnsfunc=fake_dnsfunc)

    return patch.object(dkim.DKIM, "verify", patched)


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


@pytest.mark.asyncio
async def test_valid_signature_verifies_correctly():
    private_pem, public_key_b64 = _generate_keypair()
    signed_message = _sign_test_message(private_pem)

    mod = DkimValidatorModule()
    with _patched_verify_with_key(public_key_b64):
        out = await mod.run(mod.Input(raw_email=signed_message.decode()))

    assert out.signature_count == 1
    assert out.results[0].valid is True
    assert out.results[0].domain == "test-domain.example"
    assert out.results[0].selector == "testselector"
    assert out.results[0].algorithm == "rsa-sha256"
    assert out.results[0].key_size_bits == 2048
    assert out.overall_valid is True


@pytest.mark.asyncio
async def test_tampered_body_fails_verification():
    private_pem, public_key_b64 = _generate_keypair()
    signed_message = _sign_test_message(private_pem, body_text="Originaler Inhalt.")
    tampered = signed_message.replace(b"Originaler Inhalt.", b"MANIPULIERT!")

    mod = DkimValidatorModule()
    with _patched_verify_with_key(public_key_b64):
        out = await mod.run(mod.Input(raw_email=tampered.decode()))

    assert out.results[0].valid is False
    assert out.overall_valid is False


@pytest.mark.asyncio
async def test_wrong_public_key_fails_verification():
    """Simuliert einen Schluessel-Mismatch (z.B. abgelaufener/falscher
    DNS-Eintrag) -- mit dem PASSENDEN Key aus einem ANDEREN Paar."""
    private_pem, _ = _generate_keypair()
    _, wrong_public_key_b64 = _generate_keypair()
    signed_message = _sign_test_message(private_pem)

    mod = DkimValidatorModule()
    with _patched_verify_with_key(wrong_public_key_b64):
        out = await mod.run(mod.Input(raw_email=signed_message.decode()))

    assert out.results[0].valid is False


def test_rejects_email_without_dkim_signature():
    mod = DkimValidatorModule()
    with pytest.raises(Exception):
        mod.Input(raw_email="From: x@y.de\r\nTo: a@b.de\r\n\r\nKein DKIM hier.")


def test_rejects_empty_input():
    mod = DkimValidatorModule()
    with pytest.raises(Exception):
        mod.Input(raw_email="   ")


@pytest.mark.asyncio
async def test_normalizes_lf_only_line_endings():
    """Aus Mail-Clients/Browsern kopierter Text hat oft nur LF statt
    CRLF -- ohne Normalisierung wuerde die Kanonikalisierung falsche
    Hashes berechnen und die Pruefung faelschlich als ungueltig zeigen."""
    private_pem, public_key_b64 = _generate_keypair()
    signed_message = _sign_test_message(private_pem)
    # Simuliert Text, der beim Kopieren die CR-Zeichen verloren hat
    lf_only = signed_message.replace(b"\r\n", b"\n").decode()

    mod = DkimValidatorModule()
    with _patched_verify_with_key(public_key_b64):
        out = await mod.run(mod.Input(raw_email=lf_only))

    assert out.results[0].valid is True


def test_endpoint_available_to_regular_members(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/dkim-validator", json={"raw_email": "kein dkim hier"})
    assert r.status_code == 422

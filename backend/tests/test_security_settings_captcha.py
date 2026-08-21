"""Tests fuer die instanzweiten Captcha-Einstellungen (Turnstile/reCAPTCHA)
und deren Durchsetzung beim Login/Registrieren.
"""

from unittest.mock import AsyncMock, patch

import pytest

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def _enable_captcha(client) -> None:
    client.patch(
        "/api/v1/security-settings",
        json={
            "provider": "turnstile", "enabled": True,
            "site_key": "site123", "secret_key": "secret123",
            "on_login": True, "on_register": True,
        },
    )


# --- Endpunkte ---------------------------------------------------------------

def test_public_captcha_settings_default_disabled(client):
    r = client.get("/api/v1/security-settings/public")
    assert r.status_code == 200
    assert r.json() == {"provider": "none", "enabled": False, "site_key": None, "on_login": True, "on_register": True}


def test_admin_captcha_settings_requires_auth(client):
    r = client.get("/api/v1/security-settings")
    assert r.status_code == 401

    r = client.patch("/api/v1/security-settings", json={"provider": "none", "enabled": False})
    assert r.status_code == 401


def test_admin_captcha_settings_requires_admin_role(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.get("/api/v1/security-settings")
    assert r.status_code == 403


def test_admin_can_configure_captcha(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch(
        "/api/v1/security-settings",
        json={"provider": "turnstile", "enabled": True, "site_key": "site123", "secret_key": "secret123", "on_login": True, "on_register": False},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "turnstile"
    assert body["site_key"] == "site123"
    assert body["secret_key"] == "secret123"
    assert body["on_register"] is False


def test_public_endpoint_never_exposes_secret_key(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _enable_captcha(client)

    r = client.get("/api/v1/security-settings/public")
    assert "secret_key" not in r.json()
    assert r.json()["site_key"] == "site123"
    assert r.json()["enabled"] is True


def test_update_rejects_invalid_provider(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/security-settings", json={"provider": "not-a-real-provider", "enabled": True})
    assert r.status_code == 422


def test_omitting_secret_key_does_not_clear_existing_one(client):
    """Das Frontend soll den Secret-Key beim Bearbeiten leer lassen koennen
    (z.B. weil er aus Sicherheitsgruenden nicht vorausgefuellt wird), ohne
    dass dabei ein bereits gespeicherter Key geloescht wird."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _enable_captcha(client)

    r = client.patch(
        "/api/v1/security-settings",
        json={"provider": "turnstile", "enabled": True, "site_key": "site123", "on_login": True, "on_register": True},
    )
    assert r.status_code == 200
    assert r.json()["secret_key"] == "secret123"


# --- Durchsetzung beim Login/Registrieren ------------------------------------

def test_login_unaffected_when_captcha_disabled(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.cookies.clear()

    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert r.status_code == 200


def test_login_blocked_without_valid_captcha_when_enabled(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _enable_captcha(client)
    client.cookies.clear()

    with patch("app.api.v1.endpoints.auth.verify_captcha", new=AsyncMock(return_value=False)):
        r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert r.status_code == 400


def test_login_succeeds_with_valid_captcha_when_enabled(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _enable_captcha(client)
    client.cookies.clear()

    with patch("app.api.v1.endpoints.auth.verify_captcha", new=AsyncMock(return_value=True)):
        r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password, "captcha_token": "valid-token"})
    assert r.status_code == 200


def test_login_unaffected_when_captcha_disabled_for_login_only(client):
    """on_login=False soll den Login-Endpunkt nicht blocken, obwohl
    Captcha global aktiviert ist."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.patch(
        "/api/v1/security-settings",
        json={"provider": "turnstile", "enabled": True, "site_key": "site123", "secret_key": "secret123", "on_login": False, "on_register": True},
    )
    client.cookies.clear()

    with patch("app.api.v1.endpoints.auth.verify_captcha", new=AsyncMock(return_value=False)):
        r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert r.status_code == 200


def test_incomplete_captcha_config_does_not_block_login(client):
    """Aktiviert, aber ohne vollstaendige Konfiguration (kein Secret-Key)
    -- darf niemanden aussperren."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.patch(
        "/api/v1/security-settings",
        json={"provider": "turnstile", "enabled": True, "site_key": "site123", "on_login": True, "on_register": True},
    )
    client.cookies.clear()

    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert r.status_code == 200


# --- captcha.py Kernlogik -----------------------------------------------------

def test_is_captcha_required_false_by_default(client):
    from app.core.captcha import is_captcha_required
    from app.core.db import SessionLocal

    db = SessionLocal()
    assert is_captcha_required(db, "login") is False
    assert is_captcha_required(db, "register") is False
    db.close()


@pytest.mark.asyncio
async def test_verify_captcha_noop_when_disabled(client):
    from app.core.captcha import verify_captcha
    from app.core.db import SessionLocal

    db = SessionLocal()
    result = await verify_captcha(db, None)
    assert result is True
    db.close()


@pytest.mark.asyncio
async def test_verify_captcha_fails_closed_without_token_when_enabled(client):
    from app.core.captcha import verify_captcha
    from app.core.db import SessionLocal
    from app.models.user import SecuritySettings

    db = SessionLocal()
    settings = SecuritySettings(id=1, captcha_provider="turnstile", captcha_enabled=True, captcha_site_key="x", captcha_secret_key="y")
    db.add(settings)
    db.commit()

    result = await verify_captcha(db, None)
    assert result is False
    db.close()

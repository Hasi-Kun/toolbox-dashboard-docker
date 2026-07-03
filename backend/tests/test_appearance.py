"""Tests fuer die instanzweiten Appearance-Settings (Login-Hintergrund)."""

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def test_appearance_is_publicly_readable_without_auth(client):
    r = client.get("/api/v1/appearance")
    assert r.status_code == 200
    assert r.json()["background_style"] == "dots"  # Default


def test_appearance_update_requires_auth(client):
    r = client.patch("/api/v1/appearance", json={"background_style": "gradient"})
    assert r.status_code == 401


def test_appearance_update_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.patch("/api/v1/appearance", json={"background_style": "gradient"})
    assert r.status_code == 403


def test_appearance_rejects_invalid_style(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/appearance", json={"background_style": "not-a-real-style"})
    assert r.status_code == 422


def test_appearance_custom_requires_url(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/appearance", json={"background_style": "custom"})
    assert r.status_code == 400


def test_appearance_update_persists_and_is_publicly_visible(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch(
        "/api/v1/appearance",
        json={"background_style": "custom", "custom_background_url": "https://example.com/bg.jpg"},
    )
    assert r.status_code == 200
    assert r.json()["custom_background_url"] == "https://example.com/bg.jpg"

    client.cookies.clear()
    r = client.get("/api/v1/appearance")
    assert r.json()["background_style"] == "custom"
    assert r.json()["custom_background_url"] == "https://example.com/bg.jpg"


def test_appearance_rejects_non_http_url():
    from app.api.v1.endpoints.appearance import UpdateAppearanceRequest
    from pydantic import ValidationError
    import pytest

    with pytest.raises(ValidationError):
        UpdateAppearanceRequest(background_style="custom", custom_background_url="javascript:alert(1)")

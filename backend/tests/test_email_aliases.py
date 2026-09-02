"""Tests fuer die Email-Alias-Verwaltung. Der komplette Flow wurde
zusaetzlich end-to-end manuell verifiziert."""

import pyotp
import pytest

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


@pytest.fixture(autouse=True)
def _configure_alias_domain():
    from app.core.config import get_settings

    settings = get_settings()
    original = settings.email_alias_domains
    settings.email_alias_domains = "alias.example.com"
    yield
    settings.email_alias_domains = original


def test_requires_auth(client):
    r = client.get("/api/v1/email-aliases")
    assert r.status_code == 401


def test_list_allowed_domains(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.get("/api/v1/email-aliases/domains")
    assert r.status_code == 200
    assert r.json()["domains"] == ["alias.example.com"]


def test_create_with_random_local_part(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "echt@example.de"})
    assert r.status_code == 200
    assert r.json()["address"].endswith("@alias.example.com")
    assert r.json()["enabled"] is True


def test_create_with_custom_local_part(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post(
        "/api/v1/email-aliases",
        json={"domain": "alias.example.com", "target_email": "echt@example.de", "local_part": "shop-xyz", "label": "Shop"},
    )
    assert r.status_code == 200
    assert r.json()["address"] == "shop-xyz@alias.example.com"
    assert r.json()["label"] == "Shop"


def test_rejects_duplicate_local_part(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "x@y.de", "local_part": "dup"})
    r = client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "x@y.de", "local_part": "dup"})
    assert r.status_code == 400


def test_rejects_non_allowlisted_domain(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/email-aliases", json={"domain": "nicht-konfiguriert.de", "target_email": "x@y.de"})
    assert r.status_code == 400


def test_rejects_invalid_local_part_characters(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post(
        "/api/v1/email-aliases",
        json={"domain": "alias.example.com", "target_email": "x@y.de", "local_part": "invalid;rm -rf"},
    )
    assert r.status_code == 422


def test_rejects_invalid_target_email(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "not-an-email"})
    assert r.status_code == 422


def test_toggle_enabled(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "x@y.de"})
    alias_id = r.json()["id"]

    r = client.patch(f"/api/v1/email-aliases/{alias_id}", json={"enabled": False})
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_update_target_and_label(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "x@y.de"})
    alias_id = r.json()["id"]

    r = client.patch(f"/api/v1/email-aliases/{alias_id}", json={"target_email": "neu@y.de", "label": "Neu"})
    assert r.status_code == 200
    assert r.json()["target_email"] == "neu@y.de"
    assert r.json()["label"] == "Neu"


def test_delete_alias(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "x@y.de"})
    alias_id = r.json()["id"]

    r = client.delete(f"/api/v1/email-aliases/{alias_id}")
    assert r.status_code == 200

    r = client.get("/api/v1/email-aliases")
    assert r.json() == []


def test_strict_per_user_isolation(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="bob", password_hash=hash_password("EinSicheresPasswort2"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/email-aliases", json={"domain": "alias.example.com", "target_email": "x@y.de"})
    alias_id = r.json()["id"]

    client.cookies.clear()
    _login_with_totp_setup(client, "bob", "EinSicheresPasswort2")

    r = client.get("/api/v1/email-aliases")
    assert r.json() == []

    r = client.delete(f"/api/v1/email-aliases/{alias_id}")
    assert r.status_code == 404

    r = client.patch(f"/api/v1/email-aliases/{alias_id}", json={"enabled": False})
    assert r.status_code == 404

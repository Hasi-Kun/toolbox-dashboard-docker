"""Tests fuer den DNS-Cache-Flush (AdGuard Home). Der komplette Flow
wurde zusaetzlich end-to-end manuell mit gemocktem AdGuard-Server
verifiziert (korrekte URL, Basic-Auth, JSON-Content-Type)."""

from unittest.mock import patch

import pyotp

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def test_config_requires_admin(client):
    r = client.get("/api/v1/system/dns-flush/config")
    assert r.status_code == 401


def test_default_config_not_configured(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.get("/api/v1/system/dns-flush/config")
    assert r.status_code == 200
    assert r.json()["configured"] is False


def test_flush_fails_when_not_configured(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/system/dns-flush")
    assert r.status_code == 400


def test_configure_and_flush_success(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.put(
        "/api/v1/system/dns-flush/config",
        json={"base_url": "http://adguard.local:3000", "username": "admin", "password": "geheim"},
    )
    assert r.status_code == 200
    assert r.json()["configured"] is True

    class FakeResponse:
        status_code = 200
        text = "OK"

    captured = {}

    async def fake_post(self, url, **kwargs):
        captured["url"] = url
        captured["auth"] = kwargs.get("auth")
        captured["headers"] = kwargs.get("headers")
        captured["json"] = kwargs.get("json")
        return FakeResponse()

    with patch("httpx.AsyncClient.post", new=fake_post):
        r = client.post("/api/v1/system/dns-flush")

    assert r.status_code == 200
    assert captured["url"] == "http://adguard.local:3000/control/cache_clear"
    assert captured["auth"] == ("admin", "geheim")
    assert captured["headers"]["Content-Type"] == "application/json"
    assert captured["json"] == {}


def test_flush_reports_adguard_error(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.put("/api/v1/system/dns-flush/config", json={"base_url": "http://adguard.local:3000", "username": "admin", "password": "geheim"})

    class FakeResponse:
        status_code = 415
        text = "only content-type application/json is allowed"

    async def fake_post(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.post", new=fake_post):
        r = client.post("/api/v1/system/dns-flush")

    assert r.status_code == 502


def test_flush_reports_connection_error(client):
    import httpx

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.put("/api/v1/system/dns-flush/config", json={"base_url": "http://adguard.local:3000", "username": "admin", "password": "geheim"})

    async def fake_post(self, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    with patch("httpx.AsyncClient.post", new=fake_post):
        r = client.post("/api/v1/system/dns-flush")

    assert r.status_code == 502


def test_password_never_returned_in_config_response(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.put("/api/v1/system/dns-flush/config", json={"base_url": "http://adguard.local:3000", "username": "admin", "password": "geheim-passwort"})

    r = client.get("/api/v1/system/dns-flush/config")
    assert "geheim-passwort" not in r.text
    assert "password" not in r.json()
    assert "encrypted_password" not in r.json()


def test_omitting_password_keeps_existing_one(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.put("/api/v1/system/dns-flush/config", json={"base_url": "http://adguard.local:3000", "username": "admin", "password": "erstes-passwort"})

    r = client.put("/api/v1/system/dns-flush/config", json={"base_url": "http://adguard.local:3000", "username": "admin2"})
    assert r.status_code == 200
    assert r.json()["configured"] is True
    assert r.json()["username"] == "admin2"


def test_rejects_invalid_base_url(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.put("/api/v1/system/dns-flush/config", json={"base_url": "not-a-url", "username": "admin", "password": "x"})
    assert r.status_code == 422


def test_flush_logs_audit_event(client):
    from app.core.db import SessionLocal
    from app.models.user import AuditLogEntry

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.put("/api/v1/system/dns-flush/config", json={"base_url": "http://adguard.local:3000", "username": "admin", "password": "geheim"})

    class FakeResponse:
        status_code = 200
        text = "OK"

    async def fake_post(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.post", new=fake_post):
        client.post("/api/v1/system/dns-flush")

    db = SessionLocal()
    entry = db.query(AuditLogEntry).filter_by(event_type="dns_cache_flush").first()
    db.close()
    assert entry is not None
    assert entry.success is True
    assert entry.username == "admin"


def test_flush_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/system/dns-flush")
    assert r.status_code == 403

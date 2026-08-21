"""Tests fuer Microsoft-365-SSO (OAuth2/OIDC gegen Microsoft Entra ID).
Nutzt gemockte httpx-Aufrufe fuer den Token-Austausch und Microsoft-
Graph-Abruf (echte Microsoft-Endpunkte sind aus dieser Umgebung nicht
erreichbar) -- der komplette Flow wurde zusaetzlich manuell End-to-End
verifiziert.
"""

import urllib.parse
from unittest.mock import patch

import pytest

from tests.conftest import create_admin as _create_admin


def _configure_sso():
    from app.core.config import get_settings

    settings = get_settings()
    settings.ms_sso_enabled = True
    settings.ms_sso_client_id = "test-client-id"
    settings.ms_sso_client_secret = "test-secret"
    settings.ms_sso_tenant_id = "test-tenant-id"
    return settings


def _disable_sso():
    from app.core.config import get_settings

    settings = get_settings()
    settings.ms_sso_enabled = False


class FakeTokenResponse:
    status_code = 200

    def json(self):
        return {"access_token": "fake-access-token"}


class FakeMeResponse:
    def __init__(self, upn):
        self.upn = upn
        self.status_code = 200

    def json(self):
        return {"userPrincipalName": self.upn, "displayName": "Test User"}


async def _fake_post(self, url, **kwargs):
    return FakeTokenResponse()


def test_sso_status_reflects_configuration(client):
    _configure_sso()
    r = client.get("/api/v1/auth/sso/microsoft/status")
    assert r.json()["enabled"] is True

    _disable_sso()
    r = client.get("/api/v1/auth/sso/microsoft/status")
    assert r.json()["enabled"] is False


def test_sso_login_redirects_to_microsoft(client):
    _configure_sso()
    r = client.get("/api/v1/auth/sso/microsoft/login", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "login.microsoftonline.com" in r.headers["location"]
    assert "state=" in r.headers["location"]


def test_sso_login_404_when_not_configured(client):
    _disable_sso()
    r = client.get("/api/v1/auth/sso/microsoft/login", follow_redirects=False)
    assert r.status_code == 404


def test_sso_full_login_flow_for_linked_account(client):
    from app.core.db import SessionLocal
    from app.models.user import User, UserRole

    _configure_sso()

    db = SessionLocal()
    db.add(User(username="ssouser", password_hash="unused", role=UserRole.MEMBER.value, is_active=True, microsoft_upn="max@firma.de"))
    db.commit()
    db.close()

    r = client.get("/api/v1/auth/sso/microsoft/login", follow_redirects=False)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)["state"][0]

    async def fake_get(self, url, **kwargs):
        return FakeMeResponse("max@firma.de")

    with patch("httpx.AsyncClient.post", new=_fake_post), patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get(f"/api/v1/auth/sso/microsoft/callback?code=fake-code&state={state}", follow_redirects=False)

    assert r.status_code in (302, 307)
    assert "toolbox_session" in r.cookies

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "ssouser"


def test_sso_rejects_unlinked_account(client):
    _configure_sso()

    r = client.get("/api/v1/auth/sso/microsoft/login", follow_redirects=False)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)["state"][0]

    async def fake_get(self, url, **kwargs):
        return FakeMeResponse("niemand-verknuepft@firma.de")

    with patch("httpx.AsyncClient.post", new=_fake_post), patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get(f"/api/v1/auth/sso/microsoft/callback?code=fake-code&state={state}", follow_redirects=False)

    assert r.status_code == 403


def test_sso_rejects_invalid_state(client):
    _configure_sso()
    r = client.get("/api/v1/auth/sso/microsoft/callback?code=x&state=nie-existierender-state", follow_redirects=False)
    assert r.status_code == 400


def test_sso_rejects_deactivated_linked_account(client):
    from app.core.db import SessionLocal
    from app.models.user import User, UserRole

    _configure_sso()

    db = SessionLocal()
    db.add(User(username="deaktiviert", password_hash="unused", role=UserRole.MEMBER.value, is_active=False, microsoft_upn="inactive@firma.de"))
    db.commit()
    db.close()

    r = client.get("/api/v1/auth/sso/microsoft/login", follow_redirects=False)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)["state"][0]

    async def fake_get(self, url, **kwargs):
        return FakeMeResponse("inactive@firma.de")

    with patch("httpx.AsyncClient.post", new=_fake_post), patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get(f"/api/v1/auth/sso/microsoft/callback?code=x&state={state}", follow_redirects=False)

    assert r.status_code == 403


# --- Admin-Verwaltung der microsoft_upn-Verknuepfung ------------------------

def test_admin_can_link_microsoft_upn(client):
    import pyotp
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    db = SessionLocal()
    target = User(username="targetuser", password_hash=hash_password("EinSicheresPasswort123"), role=UserRole.MEMBER.value, is_active=True)
    db.add(target)
    db.commit()
    target_id = target.id
    db.close()

    r = client.patch(f"/api/v1/users/{target_id}", json={"microsoft_upn": "target@firma.de"})
    assert r.status_code == 200
    assert r.json()["microsoft_upn"] == "target@firma.de"


def test_admin_cannot_link_duplicate_microsoft_upn(client):
    import pyotp
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    db = SessionLocal()
    user1 = User(username="user1dup", password_hash=hash_password("EinSicheresPasswort123"), role=UserRole.MEMBER.value, is_active=True, microsoft_upn="dupe@firma.de")
    user2 = User(username="user2dup", password_hash=hash_password("EinSicheresPasswort456"), role=UserRole.MEMBER.value, is_active=True)
    db.add(user1)
    db.add(user2)
    db.commit()
    user2_id = user2.id
    db.close()

    r = client.patch(f"/api/v1/users/{user2_id}", json={"microsoft_upn": "dupe@firma.de"})
    assert r.status_code == 400


def test_empty_string_clears_microsoft_upn_link(client):
    import pyotp
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    db = SessionLocal()
    target = User(username="clearme", password_hash=hash_password("EinSicheresPasswort123"), role=UserRole.MEMBER.value, is_active=True, microsoft_upn="clearme@firma.de")
    db.add(target)
    db.commit()
    target_id = target.id
    db.close()

    r = client.patch(f"/api/v1/users/{target_id}", json={"microsoft_upn": ""})
    assert r.status_code == 200
    assert r.json()["microsoft_upn"] is None

"""Tests fuer: Invite-Kontingent, Premium-Anzeigename-Customizing,
CT-Timeout-Fix, Audit-Log-IP-Fallback-Kette, OpenSSL-Text-Paste,
Google-Dork-Generator, Web-Tech-Fingerprint.
"""

import pyotp
import pytest
from unittest.mock import patch

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> str:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
    return secret


def _create_member(username: str, password: str, invite_quota: int = 0, is_premium: bool = False) -> None:
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(
        username=username, password_hash=hash_password(password), role=UserRole.MEMBER.value,
        is_active=True, invite_quota=invite_quota, is_premium=is_premium,
    ))
    db.commit()
    db.close()


def test_invite_quota_decrements_on_creation(client):
    _create_member("bob", "BobsSicheresPasswort1", invite_quota=2)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    client.post("/api/v1/invites", json={})
    assert client.get("/api/v1/auth/me").json()["invite_quota"] == 1

    client.post("/api/v1/invites", json={})
    assert client.get("/api/v1/auth/me").json()["invite_quota"] == 0

    r = client.post("/api/v1/invites", json={})
    assert r.status_code == 403


def test_admin_can_set_individual_invite_quota(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _create_member("bob", "BobsSicheresPasswort1")

    users = client.get("/api/v1/users").json()
    bob = next(u for u in users if u["username"] == "bob")
    r = client.patch(f"/api/v1/users/{bob['id']}", json={"invite_quota": 5})
    assert r.status_code == 200
    assert r.json()["invite_quota"] == 5


def test_invite_quota_rejects_out_of_range(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _create_member("bob", "BobsSicheresPasswort1")
    users = client.get("/api/v1/users").json()
    bob = next(u for u in users if u["username"] == "bob")
    r = client.patch(f"/api/v1/users/{bob['id']}", json={"invite_quota": -1})
    assert r.status_code == 422
    r = client.patch(f"/api/v1/users/{bob['id']}", json={"invite_quota": 5000})
    assert r.status_code == 422


def test_revoking_unused_invite_refunds_quota(client):
    _create_member("bob", "BobsSicheresPasswort1", invite_quota=1)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    r = client.post("/api/v1/invites", json={})
    invite_id = r.json()["id"]
    assert client.get("/api/v1/auth/me").json()["invite_quota"] == 0

    client.delete(f"/api/v1/invites/{invite_id}")
    assert client.get("/api/v1/auth/me").json()["invite_quota"] == 1


def test_admin_invite_creation_unaffected_by_quota(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    for _ in range(3):
        r = client.post("/api/v1/invites", json={})
        assert r.status_code == 200


def test_non_premium_user_cannot_set_display_style(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=False)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    r = client.patch("/api/v1/auth/me/display-style", json={
        "display_name_style": "gradient", "display_name_color": "#FF0000", "display_name_gradient_color": "#00FF00",
    })
    assert r.status_code == 403


def test_premium_user_can_set_display_style(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=True)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    r = client.patch("/api/v1/auth/me/display-style", json={
        "display_name_style": "gradient", "display_name_color": "#FF0000", "display_name_gradient_color": "#00FF00",
    })
    assert r.status_code == 200
    assert r.json()["display_name_style"] == "gradient"

    me = client.get("/api/v1/auth/me").json()
    assert me["display_name_color"] == "#FF0000"


def test_display_style_rejects_invalid_style_name(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=True)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    r = client.patch("/api/v1/auth/me/display-style", json={
        "display_name_style": "not-a-style", "display_name_color": "#FF0000", "display_name_gradient_color": "#00FF00",
    })
    assert r.status_code == 422


def test_display_style_rejects_invalid_color(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=True)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    r = client.patch("/api/v1/auth/me/display-style", json={
        "display_name_style": "solid", "display_name_color": "not-a-color", "display_name_gradient_color": "#00FF00",
    })
    assert r.status_code == 422


def test_chat_message_includes_author_display_fields(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=True)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")
    client.patch("/api/v1/auth/me/display-style", json={
        "display_name_style": "gradient", "display_name_color": "#ABCDEF", "display_name_gradient_color": "#123456",
    })

    r = client.post("/api/v1/chat/messages", json={"message": "Hallo mit Style"})
    assert r.json()["display_name_style"] == "gradient"
    assert r.json()["display_name_color"] == "#ABCDEF"
    assert r.json()["role"] == "member"


def test_premium_user_can_set_glitter_and_rainbow_styles(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=True)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    for style in ["glitter", "rainbow"]:
        r = client.patch("/api/v1/auth/me/display-style", json={
            "display_name_style": style, "display_name_color": "#FF00FF", "display_name_gradient_color": "#00FFFF",
        })
        assert r.status_code == 200, style
        assert r.json()["display_name_style"] == style


def test_feature_request_includes_author_display_fields(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=True)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")
    client.patch("/api/v1/auth/me/display-style", json={
        "display_name_style": "rainbow", "display_name_color": "#FF0000", "display_name_gradient_color": "#00FF00",
    })

    r = client.post("/api/v1/feature-requests", json={"title": "Test", "description": "Beschreibung"})
    req_id = r.json()["id"]
    assert r.json()["display_name_style"] == "rainbow"
    assert r.json()["is_premium"] is True

    client.post(f"/api/v1/feature-requests/{req_id}/comments", json={"comment": "Kommentar"})
    detail = client.get(f"/api/v1/feature-requests/{req_id}").json()
    assert detail["comments"][0]["display_name_style"] == "rainbow"

    listing = client.get("/api/v1/feature-requests").json()["items"]
    assert listing[0]["display_name_style"] == "rainbow"


def test_non_premium_user_shows_default_style_in_feature_request(client):
    _create_member("bob", "BobsSicheresPasswort1", is_premium=False)
    _login_with_totp_setup(client, "bob", "BobsSicheresPasswort1")

    r = client.post("/api/v1/feature-requests", json={"title": "Test", "description": "Beschreibung"})
    assert r.json()["display_name_style"] == "default"
    assert r.json()["is_premium"] is False


@pytest.mark.asyncio
async def test_ct_log_retries_transient_502_and_succeeds():
    from app.modules.certificates.certificate_transparency import CertificateTransparencyModule

    call_count = 0

    class FakeResponse502:
        status_code = 502

    class FakeResponse200:
        status_code = 200

        def json(self):
            return [{"id": 1, "issuer_name": "CA", "common_name": "example.com", "name_value": "example.com",
                      "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00", "serial_number": "aa"}]

    async def flaky_get(self, url, **kwargs):
        nonlocal call_count
        call_count += 1
        return FakeResponse502() if call_count < 3 else FakeResponse200()

    with patch("httpx.AsyncClient.get", new=flaky_get):
        result = await CertificateTransparencyModule().run(CertificateTransparencyModule.Input(domain="example.com"))

    assert call_count == 3
    assert result.success is True


@pytest.mark.asyncio
async def test_ct_log_gives_up_cleanly_after_persistent_502():
    import time
    from app.modules.certificates.certificate_transparency import CertificateTransparencyModule

    call_count = 0

    class FakeResponse502:
        status_code = 502

    async def always_502(self, url, **kwargs):
        nonlocal call_count
        call_count += 1
        return FakeResponse502()

    with patch("httpx.AsyncClient.get", new=always_502):
        start = time.time()
        result = await CertificateTransparencyModule().run(CertificateTransparencyModule.Input(domain="example.com"))
        duration = time.time() - start

    assert call_count == 3
    assert result.success is False
    assert duration < 10, "Darf nicht bis zum Modul-Timeout durchlaufen -- muss nach 3 Versuchen sauber aufgeben"


def test_ct_log_timeout_returns_clean_error_not_504(client):
    import httpx

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    async def slow_get(self, url, **kwargs):
        raise httpx.ReadTimeout("Simulierter Timeout")

    with patch("httpx.AsyncClient.get", new=slow_get):
        r = client.post("/api/v1/tools/certificate-transparency", json={"domain": "example.com"})

    assert r.status_code == 200
    assert r.json()["success"] is False


def test_get_client_ip_prefers_x_real_ip():
    from app.core.audit import get_client_ip

    class FakeRequest:
        headers = {"x-real-ip": "203.0.113.1", "cf-connecting-ip": "203.0.113.2", "x-forwarded-for": "203.0.113.3"}
        client = None

    assert get_client_ip(FakeRequest()) == "203.0.113.1"


def test_get_client_ip_falls_back_to_cf_connecting_ip():
    from app.core.audit import get_client_ip

    class FakeRequest:
        headers = {"cf-connecting-ip": "203.0.113.2", "x-forwarded-for": "203.0.113.3"}
        client = None

    assert get_client_ip(FakeRequest()) == "203.0.113.2"


def test_get_client_ip_falls_back_to_x_forwarded_for():
    from app.core.audit import get_client_ip

    class FakeRequest:
        headers = {"x-forwarded-for": "203.0.113.3, 10.0.0.1"}
        client = None

    assert get_client_ip(FakeRequest()) == "203.0.113.3"


def test_get_client_ip_falls_back_to_raw_client_when_no_headers():
    from app.core.audit import get_client_ip

    class FakeClient:
        host = "172.20.0.5"

    class FakeRequest:
        headers = {}
        client = FakeClient()

    assert get_client_ip(FakeRequest()) == "172.20.0.5"


def test_openssl_inspect_rejects_both_file_and_text(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post(
        "/api/v1/openssl-inspect",
        files={"file": ("x.pem", b"irrelevant")},
        data={"mode": "x509", "text_content": "also-something"},
    )
    assert r.status_code == 422


def test_openssl_inspect_rejects_garbage_text(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/openssl-inspect", data={"mode": "x509", "text_content": "not valid base64 or pem!!!"})
    assert r.status_code in (200, 422)


@pytest.mark.asyncio
async def test_google_dork_generator_produces_expected_dorks():
    from app.modules.osint.google_dork_generator import GoogleDorkGeneratorModule

    result = await GoogleDorkGeneratorModule().run(GoogleDorkGeneratorModule.Input(domain="example.com"))
    assert len(result.dorks) > 5
    assert any(d.query == "site:example.com" for d in result.dorks)


@pytest.mark.asyncio
async def test_tech_fingerprint_detects_signatures():
    from app.modules.osint.tech_fingerprint import TechFingerprintModule

    class FakeResponse:
        status_code = 200
        headers = {"Server": "nginx", "X-Powered-By": "PHP/8.1"}
        text = '<html><link href="/wp-content/x.css"><script src="https://www.googletagmanager.com/gtag/js"></script></html>'
        url = "https://example.com/"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await TechFingerprintModule().run(TechFingerprintModule.Input(domain="example.com"))

    assert result.success is True
    assert "nginx" in result.detected_technologies
    assert "WordPress" in result.detected_technologies
    assert "PHP" in result.detected_technologies


def test_all_new_modules_registered():
    from app.modules import get_registry

    registry = get_registry()
    for slug in ["google-dork-generator", "tech-fingerprint"]:
        assert slug in registry

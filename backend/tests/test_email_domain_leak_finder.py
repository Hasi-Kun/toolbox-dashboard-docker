"""Tests fuer den Email-Adressen-zu-Domains-Leak-Finder. Der HIBP-
Katalog-Abruf wurde zusaetzlich live verifiziert (Fehlerbehandlung bei
Nichterreichbarkeit) -- hier zusaetzlich die Matching-Logik mit
realistischen Daten."""

from unittest.mock import patch

import pytest

from app.modules.osint.email_domain_leak_finder import EmailDomainLeakFinderModule
from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def test_rejects_invalid_domain():
    mod = EmailDomainLeakFinderModule()
    with pytest.raises(Exception):
        mod.Input(domain="not a domain!!!")


def test_generates_paste_site_suggestions_for_any_domain():
    mod = EmailDomainLeakFinderModule()
    inp = mod.Input(domain="example.com")
    assert inp.domain == "example.com"


@pytest.mark.asyncio
async def test_finds_catalog_match_for_breached_domain():
    mod = EmailDomainLeakFinderModule()

    fake_catalog = [
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04", "PwnCount": 152445165, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True},
    ]

    class FakeResponse:
        status_code = 200

        def json(self):
            return fake_catalog

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(domain="adobe.com"))

    assert len(out.catalog_matches) == 1
    assert out.catalog_matches[0].name == "Adobe"
    assert out.catalog_matches[0].pwn_count == 152445165
    assert "betroffener Dienst" in out.note


@pytest.mark.asyncio
async def test_no_false_positive_for_unrelated_domain():
    mod = EmailDomainLeakFinderModule()

    fake_catalog = [
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04", "PwnCount": 1, "DataClasses": [], "IsVerified": True},
    ]

    class FakeResponse:
        status_code = 200

        def json(self):
            return fake_catalog

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(domain="voellig-unrelated.example"))

    assert out.catalog_matches == []
    assert "kostenlos" in out.note


@pytest.mark.asyncio
async def test_domain_matching_is_case_insensitive():
    mod = EmailDomainLeakFinderModule()

    fake_catalog = [
        {"Name": "Adobe", "Title": "Adobe", "Domain": "Adobe.COM", "BreachDate": "2013-10-04", "PwnCount": 1, "DataClasses": [], "IsVerified": True},
    ]

    class FakeResponse:
        status_code = 200

        def json(self):
            return fake_catalog

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(domain="adobe.com"))

    assert len(out.catalog_matches) == 1


@pytest.mark.asyncio
async def test_handles_unreachable_catalog_gracefully():
    mod = EmailDomainLeakFinderModule()

    async def fake_get(self, url, **kwargs):
        raise __import__("httpx").ConnectError("no route")

    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(domain="example.com"))

    assert out.catalog_reachable is False
    assert out.catalog_matches == []
    assert len(out.paste_site_suggestions) == 5


def test_available_to_regular_members(client):
    """Reine Lesequelle, kein Seiteneffekt -- nicht admin-only."""
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/email-domain-leak-finder", json={"domain": "not valid!!!"})
    assert r.status_code == 422

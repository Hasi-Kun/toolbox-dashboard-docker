"""Tests fuer den Subdomain-Takeover-Batch-Check. Nutzt dieselbe
Kernlogik wie der Einzel-Checker (check_subdomain_takeover, jetzt aus
subdomain_takeover_checker.py ausgelagert) -- hier speziell die
Batch-Aspekte: mehrere Subdomains gleichzeitig, Mengenbegrenzung,
korrekte Aggregation."""

from unittest.mock import patch

import pytest

from app.modules.osint.subdomain_takeover_batch_checker import SubdomainTakeoverBatchCheckerModule
from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


async def _fake_query(name, record_type, nameserver=None, timeout=5.0):
    if "vulnerable" in name:
        return {"success": True, "records": ["ghost-app.herokuapp.com."], "ttl": 300, "error": None}
    if "claimed" in name:
        return {"success": True, "records": ["real-app.herokuapp.com."], "ttl": 300, "error": None}
    return {"success": False, "records": [], "ttl": None, "error": "NXDOMAIN"}


class _FakeHttpResponse:
    def __init__(self, text):
        self.text = text


async def _fake_get(self, url, **kwargs):
    if "vulnerable" in url:
        return _FakeHttpResponse("No such app")
    return _FakeHttpResponse("Willkommen")


def test_rejects_empty_list():
    mod = SubdomainTakeoverBatchCheckerModule()
    with pytest.raises(Exception):
        mod.Input(subdomains="   \n  \n")


def test_rejects_too_many_subdomains():
    mod = SubdomainTakeoverBatchCheckerModule()
    with pytest.raises(Exception):
        mod.Input(subdomains="\n".join(f"sub{i}.example.com" for i in range(60)))


def test_rejects_invalid_hostname_in_list():
    mod = SubdomainTakeoverBatchCheckerModule()
    with pytest.raises(Exception):
        mod.Input(subdomains="valid.example.com\nnot valid!!!")


@pytest.mark.asyncio
async def test_checks_all_subdomains_and_aggregates_correctly():
    mod = SubdomainTakeoverBatchCheckerModule()
    subdomains = "vulnerable.example.com\nclaimed.example.com\nsafe.example.com"

    with patch("app.modules.osint.subdomain_takeover_checker.query", new=_fake_query), \
         patch("httpx.AsyncClient.get", new=_fake_get):
        out = await mod.run(mod.Input(subdomains=subdomains))

    assert out.checked_count == 3
    assert out.potentially_vulnerable_count == 1
    vuln = next(r for r in out.results if r.subdomain == "vulnerable.example.com")
    assert vuln.potentially_vulnerable is True
    safe = next(r for r in out.results if r.subdomain == "safe.example.com")
    assert safe.potentially_vulnerable is False


@pytest.mark.asyncio
async def test_all_clean_gives_zero_vulnerable_count():
    mod = SubdomainTakeoverBatchCheckerModule()

    async def all_safe_query(name, record_type, nameserver=None, timeout=5.0):
        return {"success": False, "records": [], "ttl": None, "error": "NXDOMAIN"}

    with patch("app.modules.osint.subdomain_takeover_checker.query", new=all_safe_query):
        out = await mod.run(mod.Input(subdomains="a.example.com\nb.example.com"))

    assert out.checked_count == 2
    assert out.potentially_vulnerable_count == 0


def test_endpoint_available_to_regular_members(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/subdomain-takeover-batch-checker", json={"subdomains": ""})
    assert r.status_code == 422

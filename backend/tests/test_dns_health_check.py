"""Tests fuer DNS Health Check. Live gegen google.com verifiziert (echte,
gut konfigurierte Domain) -- hier zusaetzlich kontrollierte Einzelfaelle
fuer jede Check-Kategorie."""

from unittest.mock import patch

import pytest

from app.modules.dns.dns_health_check import DnsHealthCheckModule


def _ok(records):
    return {"success": True, "records": records, "ttl": 300, "error": None}


def _fail():
    return {"success": False, "records": [], "ttl": None, "error": "NXDOMAIN"}


def test_rejects_invalid_domain():
    mod = DnsHealthCheckModule()
    with pytest.raises(Exception):
        mod.Input(domain="not a domain!!!")


@pytest.mark.asyncio
async def test_fully_healthy_domain():
    mod = DnsHealthCheckModule()

    async def fake_query(name, record_type, nameserver=None, timeout=5.0):
        if record_type in ("A",):
            return _ok(["1.2.3.4"])
        if record_type == "AAAA":
            return _ok([])
        if record_type == "MX":
            return _ok(["10 mail.example.com."])
        if record_type == "NS":
            return _ok(["ns1.example.com.", "ns2.example.com."])
        if record_type == "SOA":
            return _ok(["ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 3600"])
        if record_type == "CAA":
            return _ok(['0 issue "letsencrypt.org"'])
        if record_type == "TXT":
            if "_dmarc" in name:
                return _ok(["v=DMARC1; p=reject"])
            return _ok(["v=spf1 include:_spf.example.com ~all"])
        return _fail()

    with patch("app.modules.dns.dns_health_check.query", new=fake_query):
        out = await mod.run(mod.Input(domain="example.com"))

    assert out.overall_status == "healthy"
    assert all(c.status == "ok" for c in out.checks)


@pytest.mark.asyncio
async def test_missing_a_record_is_an_issue():
    mod = DnsHealthCheckModule()

    async def fake_query(name, record_type, nameserver=None, timeout=5.0):
        if record_type in ("A", "AAAA"):
            return _fail()
        if record_type == "NS":
            return _ok(["ns1.example.com.", "ns2.example.com."])
        if record_type == "SOA":
            return _ok(["ns1.example.com. admin.example.com. 1 3600 900 1209600 3600"])
        return _fail()

    with patch("app.modules.dns.dns_health_check.query", new=fake_query):
        out = await mod.run(mod.Input(domain="example.com"))

    assert out.overall_status == "issues"
    a_check = next(c for c in out.checks if c.name == "A/AAAA-Record")
    assert a_check.status == "missing"


@pytest.mark.asyncio
async def test_single_nameserver_is_a_warning():
    mod = DnsHealthCheckModule()

    async def fake_query(name, record_type, nameserver=None, timeout=5.0):
        if record_type == "A":
            return _ok(["1.2.3.4"])
        if record_type == "NS":
            return _ok(["ns1.example.com."])
        if record_type == "SOA":
            return _ok(["ns1.example.com. admin.example.com. 1 3600 900 1209600 3600"])
        return _fail()

    with patch("app.modules.dns.dns_health_check.query", new=fake_query):
        out = await mod.run(mod.Input(domain="example.com"))

    ns_check = next(c for c in out.checks if c.name == "Nameserver")
    assert ns_check.status == "warning"
    assert out.overall_status in ("warnings", "issues")


@pytest.mark.asyncio
async def test_missing_spf_and_dmarc_are_warnings_not_issues():
    """Fehlendes SPF/DMARC ist ein Verbesserungspunkt, kein kritischer
    Fehler -- viele legitime Domains (z.B. reine Webseiten ohne
    E-Mail-Versand) haben bewusst keins."""
    mod = DnsHealthCheckModule()

    async def fake_query(name, record_type, nameserver=None, timeout=5.0):
        if record_type == "A":
            return _ok(["1.2.3.4"])
        if record_type == "NS":
            return _ok(["ns1.example.com.", "ns2.example.com."])
        if record_type == "SOA":
            return _ok(["ns1.example.com. admin.example.com. 1 3600 900 1209600 3600"])
        if record_type == "TXT":
            return _ok([])
        return _fail()

    with patch("app.modules.dns.dns_health_check.query", new=fake_query):
        out = await mod.run(mod.Input(domain="example.com"))

    assert out.overall_status == "warnings"
    spf_check = next(c for c in out.checks if c.name == "SPF")
    dmarc_check = next(c for c in out.checks if c.name == "DMARC")
    assert spf_check.status == "warning"
    assert dmarc_check.status == "warning"


@pytest.mark.asyncio
async def test_soa_expire_less_than_refresh_flagged():
    mod = DnsHealthCheckModule()

    async def fake_query(name, record_type, nameserver=None, timeout=5.0):
        if record_type == "A":
            return _ok(["1.2.3.4"])
        if record_type == "NS":
            return _ok(["ns1.example.com.", "ns2.example.com."])
        if record_type == "SOA":
            # expire (100) < refresh (3600) -- unueblich
            return _ok(["ns1.example.com. admin.example.com. 1 3600 900 100 3600"])
        return _fail()

    with patch("app.modules.dns.dns_health_check.query", new=fake_query):
        out = await mod.run(mod.Input(domain="example.com"))

    soa_check = next(c for c in out.checks if c.name == "SOA-Werte")
    assert soa_check.status == "warning"


def test_available_to_regular_members(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole
    import pyotp

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    r = client.post("/api/v1/auth/login", json={"username": "member1", "password": "AuchEinSicheresPW123"})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})

    r = client.post("/api/v1/tools/dns-health-check", json={"domain": "not valid!!!"})
    assert r.status_code == 422

"""Tests fuer: erweiterten DNS-Lookup (mehrere Record-Typen + Custom-
Nameserver), echte SPF-IP-Validierung (rekursive Auswertung).
"""

from unittest.mock import patch

import pytest
from pydantic import ValidationError


def test_dns_lookup_rejects_unknown_record_type():
    from app.modules.dns.lookup import DnsLookupModule

    with pytest.raises(ValidationError):
        DnsLookupModule.Input(domain="example.com", record_types=["A", "NOTAREALTYPE"])


def test_dns_lookup_rejects_invalid_custom_nameserver():
    from app.modules.dns.lookup import DnsLookupModule

    with pytest.raises(ValidationError):
        DnsLookupModule.Input(domain="example.com", record_types=["A"], custom_nameserver="not-an-ip")


def test_dns_lookup_normalizes_record_types_to_uppercase():
    from app.modules.dns.lookup import DnsLookupModule

    i = DnsLookupModule.Input(domain="example.com", record_types=["a", "mx"])
    assert i.record_types == ["A", "MX"]


def test_dns_lookup_default_record_types():
    from app.modules.dns.lookup import DnsLookupModule

    i = DnsLookupModule.Input(domain="example.com")
    assert i.record_types == ["A", "AAAA", "MX", "TXT", "NS"]


@pytest.mark.asyncio
async def test_dns_lookup_queries_all_requested_types_in_parallel():
    from app.modules.dns.lookup import DnsLookupModule

    async def fake_query(domain, record_type, nameserver=None, timeout=5.0):
        return {"success": True, "records": [f"{record_type}-result"], "ttl": 300, "error": None}

    with patch("app.modules.dns.lookup.query", new=fake_query):
        result = await DnsLookupModule().run(DnsLookupModule.Input(domain="example.com", record_types=["A", "MX", "TXT"]))

    assert len(result.results) == 3
    types_returned = {r.record_type for r in result.results}
    assert types_returned == {"A", "MX", "TXT"}
    assert all(r.success for r in result.results)


@pytest.mark.asyncio
async def test_dns_lookup_passes_custom_nameserver_through():
    from app.modules.dns.lookup import DnsLookupModule

    captured_nameservers = []

    async def fake_query(domain, record_type, nameserver=None, timeout=5.0):
        captured_nameservers.append(nameserver)
        return {"success": True, "records": [], "ttl": None, "error": None}

    with patch("app.modules.dns.lookup.query", new=fake_query):
        await DnsLookupModule().run(DnsLookupModule.Input(domain="example.com", record_types=["A"], custom_nameserver="1.1.1.1"))

    assert captured_nameservers == ["1.1.1.1"]


def test_nikto_scan_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    r = client.post("/api/v1/auth/login", json={"username": "member1", "password": "AuchEinSicheresPW123"})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    import pyotp
    code = pyotp.TOTP(r.json()["secret"]).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    r = client.post("/api/v1/tools/nikto-scan", json={"target": "example.com"})
    assert r.status_code == 403


def test_nikto_scan_rejects_invalid_target():
    from app.modules.nmap.nikto_scan import NiktoScanModule
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NiktoScanModule.Input(target="; rm -rf /")


def test_nikto_registered_as_active_scan_admin_only():
    from app.modules import get_registry

    registry = get_registry()
    assert "nikto-scan" in registry
    assert registry["nikto-scan"].requires_admin is True
    assert registry["nikto-scan"].is_active_scan is True


def test_all_new_modules_registered_dns_and_spf():
    from app.modules import get_registry

    registry = get_registry()
    assert "spf-ip-validator" in registry
    assert registry["dns-lookup"].category == "dns"


def test_spf_ip_validator_rejects_invalid_ip():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    with pytest.raises(ValidationError):
        SpfIpValidatorModule.Input(domain_or_email="example.com", ip="not-an-ip")


def test_spf_ip_validator_extracts_domain_from_email():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    i = SpfIpValidatorModule.Input(domain_or_email="user@example.com", ip="203.0.113.1")
    assert i.domain_or_email == "example.com"


async def _fake_spf_query(domain, record_type, nameserver=None, timeout=5.0):
    if domain == "example.com" and record_type == "TXT":
        return {"success": True, "records": ["v=spf1 ip4:203.0.113.0/24 include:_spf.other.com -all"], "ttl": 300, "error": None}
    if domain == "_spf.other.com" and record_type == "TXT":
        return {"success": True, "records": ["v=spf1 ip4:198.51.100.5 -all"], "ttl": 300, "error": None}
    return {"success": False, "records": [], "ttl": None, "error": "NXDOMAIN"}


@pytest.mark.asyncio
async def test_spf_ip_validator_direct_ip4_match_passes():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    with patch("app.modules.mail.spf_ip_validator.query", new=_fake_spf_query):
        result = await SpfIpValidatorModule().run(SpfIpValidatorModule.Input(domain_or_email="example.com", ip="203.0.113.55"))

    assert result.result == "pass"
    assert result.matched_mechanism == "ip4:203.0.113.0/24"
    assert len(result.trace) > 0


@pytest.mark.asyncio
async def test_spf_ip_validator_include_recursion_passes():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    with patch("app.modules.mail.spf_ip_validator.query", new=_fake_spf_query):
        result = await SpfIpValidatorModule().run(SpfIpValidatorModule.Input(domain_or_email="example.com", ip="198.51.100.5"))

    assert result.result == "pass"
    assert "include:_spf.other.com" in result.matched_mechanism


@pytest.mark.asyncio
async def test_spf_ip_validator_falls_through_to_all_fail():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    with patch("app.modules.mail.spf_ip_validator.query", new=_fake_spf_query):
        result = await SpfIpValidatorModule().run(SpfIpValidatorModule.Input(domain_or_email="example.com", ip="192.0.2.1"))

    assert result.result == "fail"
    assert result.matched_mechanism == "all"


@pytest.mark.asyncio
async def test_spf_ip_validator_no_spf_record_returns_none():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    async def no_spf_query(domain, record_type, nameserver=None, timeout=5.0):
        return {"success": True, "records": ["some other txt record"], "ttl": 300, "error": None}

    with patch("app.modules.mail.spf_ip_validator.query", new=no_spf_query):
        result = await SpfIpValidatorModule().run(SpfIpValidatorModule.Input(domain_or_email="example.com", ip="203.0.113.1"))

    assert result.result == "none"


@pytest.mark.asyncio
async def test_spf_ip_validator_multiple_records_is_permerror():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    async def dual_spf_query(domain, record_type, nameserver=None, timeout=5.0):
        return {"success": True, "records": ["v=spf1 -all", "v=spf1 +all"], "ttl": 300, "error": None}

    with patch("app.modules.mail.spf_ip_validator.query", new=dual_spf_query):
        result = await SpfIpValidatorModule().run(SpfIpValidatorModule.Input(domain_or_email="example.com", ip="203.0.113.1"))

    assert result.result == "permerror"


@pytest.mark.asyncio
async def test_spf_ip_validator_softfail_qualifier():
    from app.modules.mail.spf_ip_validator import SpfIpValidatorModule

    async def softfail_query(domain, record_type, nameserver=None, timeout=5.0):
        return {"success": True, "records": ["v=spf1 ip4:203.0.113.0/24 ~all"], "ttl": 300, "error": None}

    with patch("app.modules.mail.spf_ip_validator.query", new=softfail_query):
        result = await SpfIpValidatorModule().run(SpfIpValidatorModule.Input(domain_or_email="example.com", ip="192.0.2.99"))

    assert result.result == "softfail"
    assert result.matched_mechanism == "all"

"""Tests fuer: drei neue nmap-Templates (Host-Discovery, Full-Port-Scan,
Vuln-Scan) und zwei neue OSINT-Tools (Typosquat-Checker,
Subdomain-Takeover-Checker).
"""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from tests.conftest import create_admin as _create_admin


def test_nmap_host_discovery_rejects_invalid_target():
    from app.modules.nmap.host_discovery import NmapHostDiscoveryModule
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NmapHostDiscoveryModule.Input(target="127.0.0.1; rm -rf /")


def test_nmap_full_port_scan_rejects_invalid_target():
    from app.modules.nmap.full_port_scan import NmapFullPortScanModule
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NmapFullPortScanModule.Input(target="127.0.0.1; rm -rf /")


def test_nmap_vuln_scan_rejects_invalid_target():
    from app.modules.nmap.vuln_scan import NmapVulnScanModule
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NmapVulnScanModule.Input(target="127.0.0.1; rm -rf /")


def test_all_new_nmap_and_osint_modules_registered():
    from app.modules import get_registry

    registry = get_registry()
    for slug in ["nmap-host-discovery", "nmap-full-port-scan", "nmap-vuln-scan",
                 "typosquat-checker", "subdomain-takeover-checker"]:
        assert slug in registry, f"{slug} nicht registriert"


def test_nmap_vuln_scan_requires_admin(client):
    import pyotp
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
    code = pyotp.TOTP(r.json()["secret"]).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    r = client.post("/api/v1/tools/nmap-vuln-scan", json={"target": "example.com"})
    assert r.status_code == 403


def test_nmap_host_discovery_and_full_port_scan_not_admin_gated():
    from app.modules import get_registry

    registry = get_registry()
    assert registry["nmap-host-discovery"].requires_admin is False
    assert registry["nmap-full-port-scan"].requires_admin is False


def test_typosquat_checker_rejects_invalid_domain():
    from app.modules.osint.typosquat_checker import TyposquatCheckerModule

    with pytest.raises(ValidationError):
        TyposquatCheckerModule.Input(domain="not a domain; rm -rf /")


def test_typosquat_checker_generates_variants():
    from app.modules.osint.typosquat_checker import _generate_variants

    variants = _generate_variants("github.com")
    assert "gihub.com" in variants  # Buchstabe ausgelassen
    assert "githhub.com" in variants  # Buchstabe verdoppelt
    assert "github.net" in variants  # TLD-Wechsel
    assert "github.com" not in variants  # Original nicht in den Varianten


@pytest.mark.asyncio
async def test_typosquat_checker_finds_registered_variants():
    from app.modules.osint.typosquat_checker import TyposquatCheckerModule, _generate_variants

    # "exmple.com" ist eine tatsaechlich generierte Variante (Buchstabe 'a' ausgelassen) --
    # sicherstellen, dass unsere Testannahme zur generierten Menge passt.
    assert "exmple.com" in _generate_variants("example.com")

    async def fake_query(domain, record_type, nameserver=None, timeout=4):
        if domain == "exmple.com":
            return {"success": True, "records": ["203.0.113.1"], "error": None}
        return {"success": False, "records": [], "error": "NXDOMAIN"}

    with patch("app.modules.osint.typosquat_checker.query", new=fake_query):
        result = await TyposquatCheckerModule().run(TyposquatCheckerModule.Input(domain="example.com"))

    registered_domains = {r.domain for r in result.registered_variants}
    assert "exmple.com" in registered_domains


def test_subdomain_takeover_checker_rejects_invalid_hostname():
    from app.modules.osint.subdomain_takeover_checker import SubdomainTakeoverCheckerModule

    with pytest.raises(ValidationError):
        SubdomainTakeoverCheckerModule.Input(subdomain="not a hostname; rm -rf /")


@pytest.mark.asyncio
async def test_subdomain_takeover_checker_no_cname_is_safe():
    from app.modules.osint.subdomain_takeover_checker import SubdomainTakeoverCheckerModule

    async def fake_query(domain, record_type, nameserver=None, timeout=6):
        return {"success": False, "records": [], "error": "NXDOMAIN"}

    with patch("app.modules.osint.subdomain_takeover_checker.query", new=fake_query):
        result = await SubdomainTakeoverCheckerModule().run(SubdomainTakeoverCheckerModule.Input(subdomain="example.com"))

    assert result.potentially_vulnerable is False
    assert result.cname_target is None


@pytest.mark.asyncio
async def test_subdomain_takeover_checker_detects_vulnerable_case():
    from app.modules.osint.subdomain_takeover_checker import SubdomainTakeoverCheckerModule

    async def fake_query(domain, record_type, nameserver=None, timeout=6):
        return {"success": True, "records": ["ghost-user.herokuapp.com"], "error": None}

    class FakeResponse:
        text = "Heroku | No such app"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("app.modules.osint.subdomain_takeover_checker.query", new=fake_query), patch("httpx.AsyncClient.get", new=fake_get):
        result = await SubdomainTakeoverCheckerModule().run(SubdomainTakeoverCheckerModule.Input(subdomain="forgotten.example.com"))

    assert result.potentially_vulnerable is True
    assert result.matched_service == "Heroku"


@pytest.mark.asyncio
async def test_subdomain_takeover_checker_claimed_namespace_is_safe():
    from app.modules.osint.subdomain_takeover_checker import SubdomainTakeoverCheckerModule

    async def fake_query(domain, record_type, nameserver=None, timeout=6):
        return {"success": True, "records": ["myapp.herokuapp.com"], "error": None}

    class FakeResponse:
        text = "<html>My real running application</html>"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("app.modules.osint.subdomain_takeover_checker.query", new=fake_query), patch("httpx.AsyncClient.get", new=fake_get):
        result = await SubdomainTakeoverCheckerModule().run(SubdomainTakeoverCheckerModule.Input(subdomain="app.example.com"))

    assert result.potentially_vulnerable is False
    assert result.matched_service == "Heroku"

"""Tests fuer IP Threat Intelligence. Die einzelnen Fetch-Methoden
wurden zusaetzlich live gegen die echten kostenlosen Quellen
verifiziert (Shodan InternetDB, ip-api.com, Reverse-DNS via 8.8.8.8) --
hier wird zusaetzlich die Risikobewertungs-/Aggregationslogik mit
realistischen Daten abgedeckt (die externen APIs sind in dieser
CI-Umgebung ggf. nicht erreichbar)."""

from unittest.mock import patch

import pytest

from app.modules.osint.ip_threat_intel import IpThreatIntelModule
from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def test_rejects_invalid_ip():
    mod = IpThreatIntelModule()
    with pytest.raises(Exception):
        mod.Input(ip="not-an-ip")


@pytest.mark.asyncio
async def test_flags_elevated_risk_for_known_cves_and_tags():
    mod = IpThreatIntelModule()

    async def fake_shodan(self, ip):
        return {"ports": [22, 80], "cpes": [], "hostnames": [], "tags": ["compromised"], "vulns": ["CVE-2023-1234"]}

    async def fake_asn(self, ip):
        return {"status": "success", "country": "Germany", "isp": "X", "org": "Y", "as": "AS1 X"}

    async def fake_rdns(self, ip):
        return ["host.example.com."]

    with patch.object(IpThreatIntelModule, "_fetch_shodan", new=fake_shodan), \
         patch.object(IpThreatIntelModule, "_fetch_asn", new=fake_asn), \
         patch.object(IpThreatIntelModule, "_fetch_reverse_dns", new=fake_rdns):
        out = await mod.run(mod.Input(ip="1.2.3.4"))

    assert out.risk_level == "erhoeht"
    assert any("CVE" in r for r in out.risk_reasons)
    assert any("compromised" in r for r in out.risk_reasons)


@pytest.mark.asyncio
async def test_low_risk_when_nothing_notable():
    mod = IpThreatIntelModule()

    async def fake_shodan(self, ip):
        return {"ports": [443], "cpes": [], "hostnames": [], "tags": [], "vulns": []}

    async def fake_asn(self, ip):
        return {"status": "success", "country": "Germany", "isp": "X", "org": "Y", "as": "AS1 X"}

    async def fake_rdns(self, ip):
        return []

    with patch.object(IpThreatIntelModule, "_fetch_shodan", new=fake_shodan), \
         patch.object(IpThreatIntelModule, "_fetch_asn", new=fake_asn), \
         patch.object(IpThreatIntelModule, "_fetch_reverse_dns", new=fake_rdns):
        out = await mod.run(mod.Input(ip="5.6.7.8"))

    assert out.risk_level == "niedrig"
    assert out.risk_reasons == []


@pytest.mark.asyncio
async def test_unknown_risk_when_shodan_unreachable():
    mod = IpThreatIntelModule()

    async def fake_shodan(self, ip):
        return None

    async def fake_asn(self, ip):
        return None

    async def fake_rdns(self, ip):
        return None

    with patch.object(IpThreatIntelModule, "_fetch_shodan", new=fake_shodan), \
         patch.object(IpThreatIntelModule, "_fetch_asn", new=fake_asn), \
         patch.object(IpThreatIntelModule, "_fetch_reverse_dns", new=fake_rdns):
        out = await mod.run(mod.Input(ip="5.6.7.8"))

    assert out.risk_level == "unbekannt"
    assert out.sources_reachable == {"shodan_internetdb": False, "ip_api": False, "reverse_dns": False}


@pytest.mark.asyncio
async def test_many_open_ports_flagged_as_elevated():
    mod = IpThreatIntelModule()

    async def fake_shodan(self, ip):
        return {"ports": list(range(20, 32)), "cpes": [], "hostnames": [], "tags": [], "vulns": []}

    async def fake_asn(self, ip):
        return None

    async def fake_rdns(self, ip):
        return None

    with patch.object(IpThreatIntelModule, "_fetch_shodan", new=fake_shodan), \
         patch.object(IpThreatIntelModule, "_fetch_asn", new=fake_asn), \
         patch.object(IpThreatIntelModule, "_fetch_reverse_dns", new=fake_rdns):
        out = await mod.run(mod.Input(ip="5.6.7.8"))

    assert out.risk_level == "erhoeht"
    assert any("Ports" in r for r in out.risk_reasons)


def test_endpoint_available_to_regular_members(client):
    """Anders als log4j-vuln-tester/curl-browser ist dieses Tool NICHT
    admin-only -- reine Lesequelle ohne Seiteneffekte."""
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/ip-threat-intel", json={"ip": "not-valid"})
    # 422 (Validierungsfehler) bestaetigt, dass der Zugriff NICHT an der
    # requires_admin-Pruefung (die waere 403) gescheitert ist.
    assert r.status_code == 422

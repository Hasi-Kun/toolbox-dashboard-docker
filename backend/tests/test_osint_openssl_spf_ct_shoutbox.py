"""Tests fuer: SPF-Catch-All-Bewertung, erweiterte CT-Log-Details,
Shoutbox-Auto-Clear, OSINT-Module (Subdomain-Bruteforce, ASN-Lookup,
Wayback-History), FastViewer-Status und den OpenSSL-Datei-Upload-Endpoint.
"""

import base64
import os
import subprocess
import tempfile
from datetime import date, timedelta
from unittest.mock import patch

import pytest
import pyotp
from pydantic import ValidationError

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> str:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
    return secret


# --- SPF Catch-All -----------------------------------------------------

def test_spf_catch_all_hard_fail_is_not_flagged_as_warning():
    from app.modules.mail.spf import SpfCheckModule

    module = SpfCheckModule()
    mechanisms = module._parse("v=spf1 include:_spf.google.com -all")
    all_mech = next(m for m in mechanisms if m.mechanism == "all")
    assert all_mech.qualifier == "-"


def test_spf_catch_all_permissive_qualifiers_detected():
    from app.modules.mail.spf import SpfCheckModule

    module = SpfCheckModule()
    for raw, expected in [
        ("v=spf1 include:_spf.google.com +all", "+"),
        ("v=spf1 include:_spf.google.com all", "+"),  # impliziter Default-Qualifier
        ("v=spf1 include:_spf.google.com ?all", "?"),
        ("v=spf1 include:_spf.google.com ~all", "~"),
    ]:
        mechanisms = module._parse(raw)
        all_mech = next(m for m in mechanisms if m.mechanism == "all")
        assert all_mech.qualifier == expected, raw


# --- Certificate Transparency Details -----------------------------------

@pytest.mark.asyncio
async def test_ct_log_detailed_entries_sorted_and_expiry_flagged():
    from app.modules.certificates.certificate_transparency import CertificateTransparencyModule

    sample_entries = [
        {"id": 1, "issuer_name": "CA-A", "common_name": "new.example.com",
         "name_value": "new.example.com", "not_before": "2026-06-01T00:00:00", "not_after": "2027-06-01T00:00:00",
         "serial_number": "aa"},
        {"id": 2, "issuer_name": "CA-B", "common_name": "old.example.com",
         "name_value": "old.example.com", "not_before": "2020-01-01T00:00:00", "not_after": "2020-06-01T00:00:00",
         "serial_number": "bb"},
    ]

    class FakeResponse:
        status_code = 200

        def json(self):
            return sample_entries

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await CertificateTransparencyModule().run(CertificateTransparencyModule.Input(domain="example.com"))

    assert result.total_certificates == 2
    assert len(result.recent_certificates) == 2
    assert result.recent_certificates[0].common_name == "new.example.com"
    assert result.recent_certificates[0].is_expired is False
    assert result.recent_certificates[1].is_expired is True
    assert result.recent_certificates[1].serial_number == "bb"


# --- Shoutbox Auto-Clear -------------------------------------------------

def test_shoutbox_clears_automatically_on_new_day(client):
    from app.core.db import SessionLocal
    from app.models.user import AppearanceSettings

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    client.post("/api/v1/chat/messages", json={"message": "Nachricht von heute"})
    assert len(client.get("/api/v1/chat/messages").json()) == 1

    db = SessionLocal()
    appearance = db.get(AppearanceSettings, 1)
    appearance.chat_last_cleared_date = (date.today() - timedelta(days=1)).isoformat()
    db.add(appearance)
    db.commit()
    db.close()

    assert client.get("/api/v1/chat/messages").json() == []


def test_shoutbox_does_not_clear_twice_same_day(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    client.post("/api/v1/chat/messages", json={"message": "Erste Nachricht"})
    client.get("/api/v1/chat/messages")  # triggert den Auto-Clear-Check (No-op, gleicher Tag)
    assert len(client.get("/api/v1/chat/messages").json()) == 1


# --- OSINT: Subdomain Bruteforce -----------------------------------------

def test_subdomain_bruteforce_rejects_invalid_domain():
    from app.modules.osint.subdomain_bruteforce import SubdomainBruteforceModule

    with pytest.raises(ValidationError):
        SubdomainBruteforceModule.Input(domain="not a domain; rm -rf /")


@pytest.mark.asyncio
async def test_subdomain_bruteforce_finds_resolvable_prefixes():
    from app.modules.osint.subdomain_bruteforce import SubdomainBruteforceModule

    async def fake_query(fqdn, record_type, timeout=4):
        if fqdn.startswith("www."):
            return {"success": True, "records": ["203.0.113.1"], "error": None}
        return {"success": False, "records": [], "error": "NXDOMAIN"}

    with patch("app.modules.osint.subdomain_bruteforce.query", new=fake_query):
        result = await SubdomainBruteforceModule().run(SubdomainBruteforceModule.Input(domain="example.com"))

    assert result.checked_count > 1
    assert len(result.found) == 1
    assert result.found[0].subdomain == "www.example.com"


# --- OSINT: ASN Lookup ---------------------------------------------------

@pytest.mark.asyncio
async def test_asn_lookup_parses_as_field_correctly():
    from app.modules.osint.asn_lookup import AsnLookupModule

    sample_response = {
        "status": "success", "query": "8.8.8.8", "country": "United States",
        "isp": "Google LLC", "org": "Google Public DNS", "as": "AS15169 Google LLC",
    }

    class FakeResponse:
        def json(self):
            return sample_response

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await AsnLookupModule().run(AsnLookupModule.Input(target="8.8.8.8"))

    assert result.success is True
    assert result.asn == "AS15169"
    assert result.as_name == "Google LLC"


def test_asn_lookup_rejects_invalid_target():
    from app.modules.osint.asn_lookup import AsnLookupModule

    with pytest.raises(ValidationError):
        AsnLookupModule.Input(target="not a target; rm -rf /")


# --- OSINT: Wayback History ----------------------------------------------

@pytest.mark.asyncio
async def test_wayback_history_parses_cdx_response():
    from app.modules.osint.wayback_history import WaybackHistoryModule

    sample_rows = [
        ["urlkey", "timestamp", "original", "statuscode"],
        ["com,example)/", "20200101000000", "http://example.com/", "200"],
        ["com,example)/", "20230601000000", "http://example.com/", "200"],
    ]

    class FakeResponse:
        status_code = 200

        def json(self):
            return sample_rows

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await WaybackHistoryModule().run(WaybackHistoryModule.Input(domain="example.com"))

    assert result.success is True
    assert result.total_snapshots_shown == 2
    assert result.first_seen == "20200101000000"
    assert result.last_seen == "20230601000000"
    assert "web.archive.org/web/20200101000000" in result.snapshots[0].archive_url


@pytest.mark.asyncio
async def test_wayback_history_handles_rate_limit():
    from app.modules.osint.wayback_history import WaybackHistoryModule

    class FakeResponse:
        status_code = 429

        def json(self):
            return {}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await WaybackHistoryModule().run(WaybackHistoryModule.Input(domain="example.com"))

    assert result.success is False
    assert "429" in result.error or "rate" in result.error.lower()


# --- FastViewer Status ----------------------------------------------------

@pytest.mark.asyncio
async def test_fastviewer_status_checks_update_server_and_list():
    from app.modules.utilities.fastviewer_status import FastviewerStatusModule

    class FakeResponse:
        status_code = 200
        text = "fvsrv01.fastviewer.com\nfvsrv02.fastviewer.com"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    async def fake_query(hostname, record_type, timeout=5):
        return {"success": True, "records": ["203.0.113.5"], "error": None}

    with patch("httpx.AsyncClient.get", new=fake_get), patch("app.modules.utilities.fastviewer_status.query", new=fake_query):
        result = await FastviewerStatusModule().run(FastviewerStatusModule.Input())

    assert result.success is True
    assert result.checked_count == 3  # Update-Server + 2 aus der Liste
    assert result.online_count == 3


# --- OpenSSL File Inspector ------------------------------------------------

def _generate_test_certificate() -> bytes:
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = os.path.join(tmp_dir, "key.pem")
        cert_path = os.path.join(tmp_dir, "cert.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path, "-out", cert_path,
             "-days", "30", "-nodes", "-subj", "/CN=test.example.com"],
            capture_output=True, check=True,
        )
        with open(cert_path, "rb") as f:
            return f.read()


def test_openssl_inspect_analyzes_real_certificate(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    cert_bytes = _generate_test_certificate()
    r = client.post("/api/v1/openssl-inspect", files={"file": ("cert.pem", cert_bytes)}, data={"mode": "x509"})
    assert r.status_code == 200
    result = r.json()
    assert result["success"] is True
    assert "test.example.com" in result["output"]


def test_openssl_inspect_wrong_mode_fails_cleanly(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    cert_bytes = _generate_test_certificate()
    r = client.post("/api/v1/openssl-inspect", files={"file": ("cert.pem", cert_bytes)}, data={"mode": "csr"})
    assert r.status_code == 200
    assert r.json()["success"] is False


def test_openssl_inspect_rejects_invalid_mode(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/openssl-inspect", files={"file": ("x.pem", b"irrelevant")}, data={"mode": "not-a-mode"})
    assert r.status_code == 422


def test_openssl_inspect_rejects_empty_file(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/openssl-inspect", files={"file": ("empty.pem", b"")}, data={"mode": "x509"})
    assert r.status_code == 422


def test_openssl_inspect_rejects_oversized_file(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    big_content = b"x" * 2_000_000
    r = client.post("/api/v1/openssl-inspect", files={"file": ("big.pem", big_content)}, data={"mode": "x509"})
    assert r.status_code == 413


def test_openssl_inspect_requires_auth(client):
    r = client.post("/api/v1/openssl-inspect", files={"file": ("x.pem", b"irrelevant")}, data={"mode": "x509"})
    assert r.status_code == 401


def test_openssl_inspect_cleans_up_temp_file(client, tmp_path):
    import glob
    import tempfile as tempfile_module

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    tmp_dir = tempfile_module.gettempdir()
    before = set(glob.glob(os.path.join(tmp_dir, "*.upload")))

    cert_bytes = _generate_test_certificate()
    client.post("/api/v1/openssl-inspect", files={"file": ("cert.pem", cert_bytes)}, data={"mode": "x509"})

    after = set(glob.glob(os.path.join(tmp_dir, "*.upload")))
    assert after == before, "Es duerfen keine temporaeren Upload-Dateien liegen bleiben"


def test_all_new_modules_registered():
    from app.modules import get_registry

    registry = get_registry()
    for slug in ["subdomain-bruteforce", "asn-lookup", "wayback-history", "fastviewer-status"]:
        assert slug in registry, f"{slug} nicht registriert"

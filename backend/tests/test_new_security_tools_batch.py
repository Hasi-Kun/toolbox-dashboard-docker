"""Tests fuer die neuen Security-/OSINT-Tools: TLS-Cipher-Audit, CORS-
Checker, Zone-Transfer-Check, Security-Headers-Note, Passwort-Leak-
Check, JWT-Security-Analyse, Cloud-Bucket-Finder, Git-Secrets-Scanner.
"""

import base64
import hashlib
import hmac
import json
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from tests.conftest import create_admin as _create_admin


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# --- TLS Cipher Audit -----------------------------------------------------

def test_tls_cipher_audit_rejects_invalid_host():
    from app.modules.security.tls_cipher_audit import TlsCipherAuditModule

    with pytest.raises(ValidationError):
        TlsCipherAuditModule.Input(host="not a host; rm -rf /")


def test_tls_cipher_audit_rejects_invalid_port():
    from app.modules.security.tls_cipher_audit import TlsCipherAuditModule

    with pytest.raises(ValidationError):
        TlsCipherAuditModule.Input(host="example.com", port=99999)


@pytest.mark.asyncio
async def test_tls_cipher_audit_flags_weak_cipher():
    from app.modules.security.tls_cipher_audit import TlsCipherAuditModule

    def fake_test(host, port, name, version, timeout):
        if name == "TLS 1.2":
            return {"supported": True, "cipher": "ECDHE-RSA-RC4-SHA", "note": None}
        if name == "TLS 1.0":
            return {"supported": True, "cipher": "AES128-SHA", "note": None}
        return {"supported": False, "cipher": None, "note": None}

    with patch("app.modules.security.tls_cipher_audit._test_protocol_version", new=fake_test):
        result = await TlsCipherAuditModule().run(TlsCipherAuditModule.Input(host="example.com"))

    assert result.success is True
    assert result.overall_risk == "hoch"
    tls12 = next(p for p in result.protocols if p.protocol == "TLS 1.2")
    assert tls12.weak_cipher is True
    tls10 = next(p for p in result.protocols if p.protocol == "TLS 1.0")
    assert tls10.deprecated is True


@pytest.mark.asyncio
async def test_tls_cipher_audit_low_risk_for_modern_config():
    from app.modules.security.tls_cipher_audit import TlsCipherAuditModule

    def fake_test(host, port, name, version, timeout):
        if name == "TLS 1.3":
            return {"supported": True, "cipher": "TLS_AES_256_GCM_SHA384", "note": None}
        if name == "TLS 1.2":
            return {"supported": True, "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "note": None}
        return {"supported": False, "cipher": None, "note": None}

    with patch("app.modules.security.tls_cipher_audit._test_protocol_version", new=fake_test):
        result = await TlsCipherAuditModule().run(TlsCipherAuditModule.Input(host="example.com"))

    assert result.overall_risk == "niedrig"


@pytest.mark.asyncio
async def test_tls_cipher_audit_unreachable_host():
    from app.modules.security.tls_cipher_audit import TlsCipherAuditModule

    def fake_test(host, port, name, version, timeout):
        return {"supported": None, "cipher": None, "note": "Verbindung fehlgeschlagen"}

    with patch("app.modules.security.tls_cipher_audit._test_protocol_version", new=fake_test):
        result = await TlsCipherAuditModule().run(TlsCipherAuditModule.Input(host="unreachable.invalid"))

    assert result.success is False


# --- CORS Checker ----------------------------------------------------------

def test_cors_checker_rejects_invalid_url():
    from app.modules.security.cors_checker import CorsMisconfigCheckerModule

    with pytest.raises(ValidationError):
        CorsMisconfigCheckerModule.Input(url="not a url; rm -rf /")


@pytest.mark.asyncio
async def test_cors_checker_detects_critical_misconfiguration():
    from app.modules.security.cors_checker import CorsMisconfigCheckerModule, _PROBE_ORIGIN

    class FakeResponse:
        status_code = 200
        headers = {"Access-Control-Allow-Origin": _PROBE_ORIGIN, "Access-Control-Allow-Credentials": "true"}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await CorsMisconfigCheckerModule().run(CorsMisconfigCheckerModule.Input(url="https://vulnerable.example.com"))

    assert result.risk == "kritisch"
    assert result.reflects_arbitrary_origin is True


@pytest.mark.asyncio
async def test_cors_checker_no_issue_for_wildcard_without_credentials():
    from app.modules.security.cors_checker import CorsMisconfigCheckerModule

    class FakeResponse:
        status_code = 200
        headers = {"Access-Control-Allow-Origin": "*"}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await CorsMisconfigCheckerModule().run(CorsMisconfigCheckerModule.Input(url="https://api.example.com"))

    assert result.risk == "keine"


@pytest.mark.asyncio
async def test_cors_checker_no_header_at_all():
    from app.modules.security.cors_checker import CorsMisconfigCheckerModule

    class FakeResponse:
        status_code = 200
        headers = {}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await CorsMisconfigCheckerModule().run(CorsMisconfigCheckerModule.Input(url="https://example.com"))

    assert result.risk == "keine"
    assert result.acao_header is None


# --- DNS Zone Transfer Check -----------------------------------------------

def test_zone_transfer_check_rejects_invalid_domain():
    from app.modules.dns.zone_transfer_check import ZoneTransferCheckModule

    with pytest.raises(ValidationError):
        ZoneTransferCheckModule.Input(domain="not a domain; rm -rf /")


@pytest.mark.asyncio
async def test_zone_transfer_check_detects_vulnerable_nameserver():
    import app.modules.dns.zone_transfer_check as mod
    from app.modules.dns.zone_transfer_check import ZoneTransferCheckModule

    class FakeNSRecord:
        def __init__(self, name):
            self.target = name

    def fake_try_axfr(ip, domain, timeout):
        if ip == "203.0.113.10":
            return {"vulnerable": True, "record_count": 42, "sample_names": ["www", "mail"], "error": None}
        return {"vulnerable": False, "record_count": 0, "sample_names": [], "error": None}

    async def fake_to_thread(fn, *args, **kwargs):
        if fn is mod.dns.resolver.resolve:
            host, rtype = args[0], args[1]
            if rtype == "NS":
                return [FakeNSRecord("ns1.example.com."), FakeNSRecord("ns2.example.com.")]
            if rtype == "A":
                return ["203.0.113.10"] if host == "ns1.example.com" else ["203.0.113.20"]
        elif fn is fake_try_axfr:
            return fake_try_axfr(*args)
        raise ValueError(f"unerwarteter Aufruf: {fn}")

    with patch.object(mod.asyncio, "to_thread", new=fake_to_thread), patch.object(mod, "_try_axfr", new=fake_try_axfr):
        result = await ZoneTransferCheckModule().run(ZoneTransferCheckModule.Input(domain="example.com"))

    assert result.success is True
    assert result.any_vulnerable is True
    assert result.nameservers_checked == 2


@pytest.mark.asyncio
async def test_zone_transfer_check_no_vulnerable_nameservers():
    import app.modules.dns.zone_transfer_check as mod
    from app.modules.dns.zone_transfer_check import ZoneTransferCheckModule

    class FakeNSRecord:
        def __init__(self, name):
            self.target = name

    def fake_try_axfr(ip, domain, timeout):
        return {"vulnerable": False, "record_count": 0, "sample_names": [], "error": None}

    async def fake_to_thread(fn, *args, **kwargs):
        if fn is mod.dns.resolver.resolve:
            host, rtype = args[0], args[1]
            if rtype == "NS":
                return [FakeNSRecord("ns1.example.com.")]
            return ["203.0.113.10"]
        elif fn is fake_try_axfr:
            return fake_try_axfr(*args)
        raise ValueError("unerwartet")

    with patch.object(mod.asyncio, "to_thread", new=fake_to_thread), patch.object(mod, "_try_axfr", new=fake_try_axfr):
        result = await ZoneTransferCheckModule().run(ZoneTransferCheckModule.Input(domain="example.com"))

    assert result.any_vulnerable is False


# --- Security Headers Grade ------------------------------------------------

@pytest.mark.asyncio
async def test_security_headers_assigns_letter_grade():
    from app.modules.security.headers import SecurityHeadersModule

    class FakeResponse:
        status_code = 200
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await SecurityHeadersModule().run(SecurityHeadersModule.Input(domain="example.com"))

    assert result.grade == "A+"
    assert result.score == result.max_score


@pytest.mark.asyncio
async def test_security_headers_low_grade_for_missing_headers():
    from app.modules.security.headers import SecurityHeadersModule

    class FakeResponse:
        status_code = 200
        headers = {}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await SecurityHeadersModule().run(SecurityHeadersModule.Input(domain="example.com"))

    assert result.grade == "F"


# --- Password Breach Check --------------------------------------------------

def test_password_breach_check_rejects_empty_password():
    from app.modules.security.password_breach_check import PasswordBreachCheckModule

    with pytest.raises(ValidationError):
        PasswordBreachCheckModule.Input(password="")


def test_password_breach_check_is_redacted_from_history():
    from app.modules.security.password_breach_check import PasswordBreachCheckModule

    assert PasswordBreachCheckModule.redact_input_in_history is True


@pytest.mark.asyncio
async def test_password_breach_check_detects_known_breach():
    from app.modules.security.password_breach_check import PasswordBreachCheckModule

    test_password = "password123"
    full_hash = hashlib.sha1(test_password.encode()).hexdigest().upper()
    suffix = full_hash[5:]

    class FakeResponse:
        status_code = 200
        text = f"{suffix}:99999\nAAAA1111111111111111111111111111AAAA:3"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await PasswordBreachCheckModule().run(PasswordBreachCheckModule.Input(password=test_password))

    assert result.breached is True
    assert result.times_seen == 99999


@pytest.mark.asyncio
async def test_password_breach_check_no_match():
    from app.modules.security.password_breach_check import PasswordBreachCheckModule

    class FakeResponse:
        status_code = 200
        text = "FFFF9999999999999999999999999999FFFF:1"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await PasswordBreachCheckModule().run(PasswordBreachCheckModule.Input(password="ein-ziemlich-einzigartiges-passwort-xyz"))

    assert result.breached is False


def test_password_breach_check_not_persisted_in_history(client):
    _create_admin_pw = _create_admin()

    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": _create_admin_pw})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    class FakeResponse:
        status_code = 200
        text = "AAAA:1"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        client.post("/api/v1/tools/password-breach-check", json={"password": "mein-geheimes-testpasswort"})

    from app.core.db import SessionLocal
    from app.models.user import ToolExecution

    db = SessionLocal()
    execution = db.query(ToolExecution).filter_by(tool_slug="password-breach-check").first()
    db.close()
    assert execution is not None
    assert "mein-geheimes-testpasswort" not in (execution.input_json or "")
    assert "redacted" in execution.input_json


# --- JWT Security Analyzer --------------------------------------------------

def test_jwt_analyzer_rejects_malformed_token():
    import asyncio
    from app.modules.security.jwt_security_analyzer import JwtSecurityAnalyzerModule

    result = asyncio.run(JwtSecurityAnalyzerModule().run(JwtSecurityAnalyzerModule.Input(token="not-a-jwt")))
    assert result.valid_format is False


@pytest.mark.asyncio
async def test_jwt_analyzer_detects_alg_none():
    from app.modules.security.jwt_security_analyzer import JwtSecurityAnalyzerModule

    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "admin"}).encode())
    token = f"{header}.{payload}."

    result = await JwtSecurityAnalyzerModule().run(JwtSecurityAnalyzerModule.Input(token=token))
    assert any(f.severity == "kritisch" and "none" in f.title.lower() for f in result.findings)


@pytest.mark.asyncio
async def test_jwt_analyzer_detects_weak_hmac_secret():
    from app.modules.security.jwt_security_analyzer import JwtSecurityAnalyzerModule

    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "user1", "exp": 9999999999, "iat": 1700000000}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(b"secret", signing_input, hashlib.sha256).digest()
    token = f"{header}.{payload}.{_b64url(sig)}"

    result = await JwtSecurityAnalyzerModule().run(JwtSecurityAnalyzerModule.Input(token=token))
    assert result.weak_secret_found == "secret"


@pytest.mark.asyncio
async def test_jwt_analyzer_flags_missing_exp():
    from app.modules.security.jwt_security_analyzer import JwtSecurityAnalyzerModule

    header = _b64url(json.dumps({"alg": "HS256"}).encode())
    payload = _b64url(json.dumps({"sub": "user1"}).encode())
    token = f"{header}.{payload}.somesignature"

    result = await JwtSecurityAnalyzerModule().run(JwtSecurityAnalyzerModule.Input(token=token))
    assert any("exp" in f.title.lower() and f.severity == "hoch" for f in result.findings)


@pytest.mark.asyncio
async def test_jwt_analyzer_strong_token_has_no_critical_findings():
    from app.modules.security.jwt_security_analyzer import JwtSecurityAnalyzerModule
    import secrets as secrets_module

    header = _b64url(json.dumps({"alg": "HS256"}).encode())
    payload = _b64url(json.dumps({"sub": "user1", "exp": 9999999999, "iat": 1700000000}).encode())
    signing_input = f"{header}.{payload}".encode()
    strong_secret = secrets_module.token_urlsafe(32)
    sig = hmac.new(strong_secret.encode(), signing_input, hashlib.sha256).digest()
    token = f"{header}.{payload}.{_b64url(sig)}"

    result = await JwtSecurityAnalyzerModule().run(JwtSecurityAnalyzerModule.Input(token=token))
    assert result.weak_secret_found is None
    assert not any(f.severity == "kritisch" for f in result.findings)


# --- Cloud Bucket Finder -----------------------------------------------------

def test_cloud_bucket_finder_rejects_too_short_name():
    from app.modules.osint.cloud_bucket_finder import CloudBucketFinderModule

    with pytest.raises(ValidationError):
        CloudBucketFinderModule.Input(name="ab")


def test_cloud_bucket_finder_sanitizes_domain_input():
    from app.modules.osint.cloud_bucket_finder import CloudBucketFinderModule

    result = CloudBucketFinderModule.Input(name="example.com")
    assert result.name == "example"


@pytest.mark.asyncio
async def test_cloud_bucket_finder_detects_public_and_private_buckets():
    from app.modules.osint.cloud_bucket_finder import CloudBucketFinderModule

    class FakeResponse:
        def __init__(self, status_code):
            self.status_code = status_code

    async def fake_get(self, url, **kwargs):
        if "public-test" in url and "s3.amazonaws.com" in url:
            return FakeResponse(200)
        if "private-test" in url and "s3.amazonaws.com" in url:
            return FakeResponse(403)
        return FakeResponse(404)

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await CloudBucketFinderModule().run(CloudBucketFinderModule.Input(name="public-test"))
    s3_hits = [f for f in result.found if f.provider == "S3"]
    assert any(f.publicly_listable for f in s3_hits)


# --- Git Secrets Scanner -----------------------------------------------------

def test_git_secrets_scanner_requires_token():
    from app.modules.osint.git_secrets_scanner import GitSecretsScannerModule

    with pytest.raises(ValidationError):
        GitSecretsScannerModule.Input(query="example.com", github_token="")


def test_git_secrets_scanner_is_redacted_from_history():
    from app.modules.osint.git_secrets_scanner import GitSecretsScannerModule

    assert GitSecretsScannerModule.redact_input_in_history is True


@pytest.mark.asyncio
async def test_git_secrets_scanner_parses_matches():
    from app.modules.osint.git_secrets_scanner import GitSecretsScannerModule

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"total_count": 1, "items": [
                {"repository": {"full_name": "someuser/leaky-repo"}, "path": ".env", "html_url": "https://github.com/someuser/leaky-repo/blob/main/.env"},
            ]}

    async def fake_get(self, url, params=None, headers=None, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await GitSecretsScannerModule().run(GitSecretsScannerModule.Input(query="example.com", github_token="fake-token"))

    assert result.success is True
    assert len(result.matches) > 0
    assert result.matches[0].repository == "someuser/leaky-repo"


@pytest.mark.asyncio
async def test_git_secrets_scanner_handles_invalid_token():
    from app.modules.osint.git_secrets_scanner import GitSecretsScannerModule

    class FakeResponse:
        status_code = 401

    async def fake_get(self, url, params=None, headers=None, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await GitSecretsScannerModule().run(GitSecretsScannerModule.Input(query="example.com", github_token="invalid"))

    assert result.success is False


def test_all_new_security_modules_registered():
    from app.modules import get_registry

    registry = get_registry()
    for slug in [
        "tls-cipher-audit", "cors-checker", "zone-transfer-check",
        "password-breach-check", "jwt-security-analyzer",
        "cloud-bucket-finder", "git-secrets-scanner",
    ]:
        assert slug in registry, f"{slug} nicht registriert"

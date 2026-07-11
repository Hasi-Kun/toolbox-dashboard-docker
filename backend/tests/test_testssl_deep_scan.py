"""Tests fuer das testssl.sh Deep-Scan-Tool (eigene Kategorie
'testssl') -- Modul-Registrierung, Admin-Sperre, Polling-Fluss,
Ergebnis-Parsing.
"""

import json

import pyotp
import pytest
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


def test_testssl_module_registered_with_own_category():
    from app.modules import get_registry

    registry = get_registry()
    assert "testssl-deep-scan" in registry
    assert registry["testssl-deep-scan"].category == "testssl"
    assert registry["testssl-deep-scan"].is_active_scan is True
    assert registry["testssl-deep-scan"].requires_admin is True


def test_testssl_input_rejects_invalid_target():
    from app.modules.testssl.deep_scan import TestsslDeepScanModule

    with pytest.raises(ValidationError):
        TestsslDeepScanModule.Input(target="; rm -rf /")


def test_testssl_input_rejects_invalid_port():
    from app.modules.testssl.deep_scan import TestsslDeepScanModule

    with pytest.raises(ValidationError):
        TestsslDeepScanModule.Input(target="example.com", port=99999)


def test_testssl_parse_scan_result_counts_vulnerabilities():
    from app.modules.testssl.deep_scan import TestsslDeepScanModule

    module = TestsslDeepScanModule()
    data = TestsslDeepScanModule.Input(target="example.com")
    raw = {
        "findings": [{"id": "SSLv3", "severity": "OK", "finding": "not offered"}],
        "vulnerabilities": [
            {"id": "ROBOT", "severity": "HIGH", "cve": "CVE-2017-13099", "finding": "VULNERABLE", "vulnerable": True},
            {"id": "heartbleed", "severity": "OK", "cve": "CVE-2014-0160", "finding": "not vulnerable", "vulnerable": False},
        ],
        "severity_counts": {"OK": 2, "HIGH": 1},
    }
    output = module.parse_scan_result(data, raw)
    assert output.success is True
    assert output.vulnerable_count == 1
    assert len(output.vulnerabilities) == 2


def test_testssl_parse_scan_result_handles_error():
    from app.modules.testssl.deep_scan import TestsslDeepScanModule

    module = TestsslDeepScanModule()
    data = TestsslDeepScanModule.Input(target="example.com")
    output = module.parse_scan_result(data, {"error": "Verbindung fehlgeschlagen"})
    assert output.success is False
    assert output.error == "Verbindung fehlgeschlagen"


def test_testssl_scan_start_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/testssl-deep-scan/scan/start", json={"target": "example.com"})
    assert r.status_code == 403


def test_testssl_full_polling_flow(client):
    import asyncio
    import app.core.scan_queue as scan_queue_module

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/testssl-deep-scan/scan/start", json={"target": "example.com"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    r = client.get(f"/api/v1/tools/testssl-deep-scan/scan/status/{job_id}")
    assert r.json()["status"] == "pending"

    asyncio.run(scan_queue_module._redis.set(
        f"scanner:result:{job_id}",
        json.dumps({
            "target": "93.184.216.34/93.184.216.34",
            "findings": [{"id": "SSLv3", "severity": "OK", "finding": "not offered"}],
            "vulnerabilities": [{"id": "ROBOT", "severity": "HIGH", "cve": "CVE-2017-13099", "finding": "VULNERABLE", "vulnerable": True}],
            "severity_counts": {"OK": 1, "HIGH": 1},
        }),
        ex=300,
    ))

    r = client.get(f"/api/v1/tools/testssl-deep-scan/scan/status/{job_id}")
    data = r.json()
    assert data["status"] == "done"
    assert data["result"]["vulnerable_count"] == 1


def test_testssl_has_stricter_per_slug_rate_limit(client):
    from app.api.v1.endpoints.tools import _PER_SLUG_SCAN_LIMITS

    assert _PER_SLUG_SCAN_LIMITS.get("testssl-deep-scan") == 2

"""Tests fuer das Polling-Muster bei aktiven Scans: POST .../scan/start
gibt sofort eine job_id zurueck, GET .../scan/status/{job_id} fragt das
Ergebnis in kurzen Anfragen ab -- statt einer einzelnen, lange offenen
HTTP-Verbindung (die bei langen Scans an Reverse-Proxy-/CDN-Timeouts wie
Cloudflares eigenem ~100s-Limit scheitern kann, unabhaengig von Caddys
eigener Konfiguration).
"""

import json

import pyotp
import pytest

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> str:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
    return secret


def test_scan_start_returns_job_id_immediately(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "example.com"})
    assert r.status_code == 200
    assert r.json()["status"] == "pending"
    assert "job_id" in r.json() and len(r.json()["job_id"]) > 10


def test_scan_status_pending_before_result_available(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "example.com"})
    job_id = r.json()["job_id"]

    r = client.get(f"/api/v1/tools/nmap-quick/scan/status/{job_id}")
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


def test_scan_status_returns_parsed_result_once_available(client):
    import asyncio
    import app.core.scan_queue as scan_queue_module

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "example.com"})
    job_id = r.json()["job_id"]

    asyncio.run(scan_queue_module._redis.set(
        f"scanner:result:{job_id}",
        json.dumps({"hosts": [{"address": "93.184.216.34", "status": "up", "ports": [], "os_guesses": []}]}),
        ex=300,
    ))

    r = client.get(f"/api/v1/tools/nmap-quick/scan/status/{job_id}")
    data = r.json()
    assert data["status"] == "done"
    assert data["result"]["success"] is True
    assert data["result"]["hosts"][0]["address"] == "93.184.216.34"


def test_scan_status_handles_error_result(client):
    import asyncio
    import app.core.scan_queue as scan_queue_module

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "example.com"})
    job_id = r.json()["job_id"]

    asyncio.run(scan_queue_module._redis.set(f"scanner:result:{job_id}", json.dumps({"error": "Simulierter Scan-Fehler"}), ex=300))

    r = client.get(f"/api/v1/tools/nmap-quick/scan/status/{job_id}")
    data = r.json()
    assert data["status"] == "done"
    assert data["result"]["success"] is False
    assert data["result"]["error"] == "Simulierter Scan-Fehler"


def test_non_scan_tool_rejects_polling_endpoint(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/dns-lookup/scan/start", json={"domain": "example.com"})
    assert r.status_code == 400


def test_scan_start_requires_admin_for_admin_gated_tools(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/nikto-scan/scan/start", json={"target": "example.com"})
    assert r.status_code == 403


def test_scan_status_rejects_other_users(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.add(User(username="member2", password_hash=hash_password("AuchEinSicheresPW456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "example.com"})
    job_id = r.json()["job_id"]
    client.cookies.clear()

    _login_with_totp_setup(client, "member2", "AuchEinSicheresPW456")
    r = client.get(f"/api/v1/tools/nmap-quick/scan/status/{job_id}")
    assert r.status_code == 403


def test_scan_status_allows_admin_to_view_any_job(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "example.com"})
    job_id = r.json()["job_id"]
    client.cookies.clear()

    admin_password = _create_admin()
    _login_with_totp_setup(client, "admin", admin_password)
    r = client.get(f"/api/v1/tools/nmap-quick/scan/status/{job_id}")
    assert r.status_code == 200


def test_scan_start_rejects_invalid_input(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "; rm -rf /"})
    assert r.status_code == 422


def test_scan_status_unknown_job_id_is_pending_not_error(client):
    """Ein unbekannter/nie existierender job_id soll nicht abstuerzen --
    einfach als 'noch nicht da' behandeln."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/tools/nmap-quick/scan/status/nie-existiert-12345")
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


def test_scan_polling_creates_history_entry_on_completion(client):
    import asyncio
    import app.core.scan_queue as scan_queue_module

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/nmap-quick/scan/start", json={"target": "example.com"})
    job_id = r.json()["job_id"]

    asyncio.run(scan_queue_module._redis.set(
        f"scanner:result:{job_id}",
        json.dumps({"hosts": [{"address": "93.184.216.34", "status": "up", "ports": [], "os_guesses": []}]}),
        ex=300,
    ))
    client.get(f"/api/v1/tools/nmap-quick/scan/status/{job_id}")

    r = client.get("/api/v1/system/scan-history")
    entries = r.json()["items"]
    assert any(e["tool_slug"] == "nmap-quick" and e["target"] == "example.com" for e in entries)


def test_scan_queue_status_empty_by_default(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/system/scan-queue-status")
    assert r.status_code == 200
    assert r.json()["current_job"] is None
    assert r.json()["queue_length"] == 0


def test_scan_queue_status_shows_current_job_and_queue_length(client):
    import asyncio
    import app.core.scan_queue as scan_queue_module

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    async def setup():
        await scan_queue_module._redis.set(
            "scanner:current-job",
            json.dumps({"job_id": "abc", "template": "nikto", "target": "example.com", "started_at": "2026-01-01T00:00:00+00:00"}),
            ex=2100,
        )
        await scan_queue_module._redis.rpush("scanner:jobs", json.dumps({"job_id": "x"}), json.dumps({"job_id": "y"}))

    asyncio.run(setup())

    r = client.get("/api/v1/system/scan-queue-status")
    data = r.json()
    assert data["current_job"]["job_id"] == "abc"
    assert data["current_job"]["target"] == "example.com"
    assert data["queue_length"] == 2


def test_scan_queue_status_requires_login(client):
    r = client.get("/api/v1/system/scan-queue-status")
    assert r.status_code == 401

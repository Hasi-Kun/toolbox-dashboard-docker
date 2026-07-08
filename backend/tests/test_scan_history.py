"""Tests fuer die Scan-Historie (admin-only Uebersicht ueber aktive
Scans, gefiltert aus der bestehenden tool_executions-Tabelle).
"""

import json

import pyotp

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> str:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
    return secret


def _insert_execution(user_id: int, tool_slug: str, success: bool, target: str, error_message: str | None = None) -> None:
    from app.core.db import SessionLocal
    from app.models.user import ToolExecution

    db = SessionLocal()
    db.add(ToolExecution(
        user_id=user_id, tool_slug=tool_slug, success=success,
        input_json=json.dumps({"target": target}), error_message=error_message,
    ))
    db.commit()
    db.close()


def test_scan_history_only_shows_active_scan_tools(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    admin_id = SessionLocal().query(User).filter_by(username="admin").first().id

    _insert_execution(admin_id, "nikto-scan", True, "bookstack.{{BASE_DOMAIN}}")
    _insert_execution(admin_id, "dns-lookup", True, "example.com")

    r = client.get("/api/v1/system/scan-history")
    data = r.json()
    assert data["total"] == 1
    assert data["items"][0]["tool_slug"] == "nikto-scan"


def test_scan_history_search_by_target(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    admin_id = SessionLocal().query(User).filter_by(username="admin").first().id

    _insert_execution(admin_id, "nikto-scan", True, "bookstack.{{BASE_DOMAIN}}")
    _insert_execution(admin_id, "nmap-quick", True, "totally-different.example.com")

    r = client.get("/api/v1/system/scan-history?search=bookstack")
    assert r.json()["total"] == 1


def test_scan_history_filter_by_tool_slug(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    admin_id = SessionLocal().query(User).filter_by(username="admin").first().id

    _insert_execution(admin_id, "nikto-scan", True, "a.example.com")
    _insert_execution(admin_id, "nmap-quick", True, "b.example.com")

    r = client.get("/api/v1/system/scan-history?tool_slug=nmap-quick")
    data = r.json()
    assert data["total"] == 1
    assert data["items"][0]["tool_slug"] == "nmap-quick"


def test_scan_history_shows_error_message_on_failure(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    admin_id = SessionLocal().query(User).filter_by(username="admin").first().id

    _insert_execution(admin_id, "nmap-quick", False, "example.com", error_message="Scan-Timeout")

    r = client.get("/api/v1/system/scan-history")
    assert r.json()["items"][0]["error_message"] == "Scan-Timeout"
    assert r.json()["items"][0]["success"] is False


def test_scan_history_tools_endpoint_lists_only_active_scans(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/system/scan-history/tools")
    tools = r.json()
    assert "nikto-scan" in tools
    assert "dns-lookup" not in tools


def test_scan_history_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    assert client.get("/api/v1/system/scan-history").status_code == 403
    assert client.get("/api/v1/system/scan-history/tools").status_code == 403


def test_scan_history_pagination(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    admin_id = SessionLocal().query(User).filter_by(username="admin").first().id

    for i in range(75):
        _insert_execution(admin_id, "nmap-quick", True, f"target{i}.example.com")

    r1 = client.get("/api/v1/system/scan-history?page=1&page_size=50")
    data1 = r1.json()
    assert len(data1["items"]) == 50
    assert data1["total"] == 75
    assert data1["total_pages"] == 2

    r2 = client.get("/api/v1/system/scan-history?page=2&page_size=50")
    assert len(r2.json()["items"]) == 25

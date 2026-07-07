"""Tests fuer: Feature-Request-Tags/Suche/Pagination, Audit-Log-Suche/
Filter/Pagination.
"""

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


def test_feature_request_tags_list_endpoint(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.get("/api/v1/feature-requests/tags")
    assert r.status_code == 200
    assert "tools" in r.json()
    assert "dashboard" in r.json()


def test_feature_request_create_with_tags(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y", "tags": ["dashboard", "ui"]})
    assert r.status_code == 200
    assert set(r.json()["tags"]) == {"dashboard", "ui"}


def test_feature_request_rejects_unknown_tag(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y", "tags": ["not-a-real-tag"]})
    assert r.status_code == 422


def test_feature_request_rejects_too_many_tags(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/feature-requests", json={
        "title": "X", "description": "Y",
        "tags": ["tools", "dashboard", "ui", "security", "performance", "other"],
    })
    assert r.status_code == 422


def test_feature_request_filter_by_tag(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.post("/api/v1/feature-requests", json={"title": "Tool Sache", "description": "x", "tags": ["tools"]})
    client.post("/api/v1/feature-requests", json={"title": "UI Sache", "description": "x", "tags": ["ui"]})

    r = client.get("/api/v1/feature-requests?tag=tools")
    data = r.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Tool Sache"


def test_feature_request_search(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.post("/api/v1/feature-requests", json={"title": "Findbares Ding", "description": "x"})
    client.post("/api/v1/feature-requests", json={"title": "Anderes", "description": "x"})

    r = client.get("/api/v1/feature-requests?search=Findbares")
    data = r.json()
    assert data["total"] == 1


def test_feature_request_pagination(client):
    from app.core.db import SessionLocal
    from app.models.user import FeatureRequest

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    db = SessionLocal()
    for i in range(32):
        db.add(FeatureRequest(username="admin", title=f"Bulk {i}", description="x"))
    db.commit()
    db.close()

    r1 = client.get("/api/v1/feature-requests?page=1&page_size=25")
    data1 = r1.json()
    assert len(data1["items"]) == 25
    assert data1["total"] == 32
    assert data1["total_pages"] == 2

    r2 = client.get("/api/v1/feature-requests?page=2&page_size=25")
    data2 = r2.json()
    assert len(data2["items"]) == 7


def test_feature_request_page_beyond_end_clamped(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y"})

    r = client.get("/api/v1/feature-requests?page=999&page_size=25")
    data = r.json()
    assert data["page"] == 1


def test_audit_log_pagination_default_100(client):
    from app.core.db import SessionLocal
    from app.models.user import AuditLogEntry

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    db = SessionLocal()
    for i in range(150):
        db.add(AuditLogEntry(event_type="login_password", username=f"user{i}", success=True, detail=f"Eintrag {i}"))
    db.commit()
    db.close()

    r = client.get("/api/v1/system/audit-log")
    data = r.json()
    assert len(data["items"]) == 100
    assert data["total_pages"] == 2


def test_audit_log_filter_by_event_type(client):
    from app.core.db import SessionLocal
    from app.models.user import AuditLogEntry

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    db = SessionLocal()
    db.add(AuditLogEntry(event_type="admin_delete_user", username="admin", success=True, detail="geloescht: bob"))
    db.commit()
    db.close()

    r = client.get("/api/v1/system/audit-log?event_type=admin_delete_user")
    data = r.json()
    assert data["total"] == 1


def test_audit_log_search(client):
    from app.core.db import SessionLocal
    from app.models.user import AuditLogEntry

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    db = SessionLocal()
    db.add(AuditLogEntry(event_type="admin_delete_user", username="admin", success=True, detail="besonderer suchbegriff xyz"))
    db.commit()
    db.close()

    r = client.get("/api/v1/system/audit-log?search=suchbegriff")
    data = r.json()
    assert data["total"] == 1


def test_audit_log_event_types_endpoint(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.get("/api/v1/system/audit-log/event-types")
    assert r.status_code == 200
    assert "login_password" in r.json()


def test_audit_log_requires_admin_for_pagination_endpoints(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    assert client.get("/api/v1/system/audit-log").status_code == 403
    assert client.get("/api/v1/system/audit-log/event-types").status_code == 403

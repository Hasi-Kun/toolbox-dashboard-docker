"""Tests fuer zwei neue Sicherheits-Features:
1. Optionale IP-Beschraenkung fuer den Login (jeder Nutzer verwaltet
   selbst, welche IPs/CIDR-Bereiche fuer sein Konto erlaubt sind).
2. Automatischer Logout -- individuelles, gleitendes Session-Timeout.
"""

import pyotp
import pytest

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str, ip: str | None = None) -> str:
    headers = {"x-real-ip": ip} if ip else {}
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password}, headers=headers)
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code}, headers=headers)
    return secret


# --- IP-Beschraenkung fuer den Login ----------------------------------------

def test_ip_restriction_validation_rejects_garbage(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/auth/me/security/allowed-ips", json={"allowed_ips": "nicht-valide-eingabe"})
    assert r.status_code == 400


def test_ip_restriction_prevents_self_lockout(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password, ip="203.0.113.50")

    # Versucht, eine Liste zu setzen, die die EIGENE aktuelle IP nicht enthaelt
    r = client.patch(
        "/api/v1/auth/me/security/allowed-ips",
        json={"allowed_ips": "198.51.100.1"},
        headers={"x-real-ip": "203.0.113.50"},
    )
    assert r.status_code == 400
    assert "aussperren" in r.json()["detail"].lower()


def test_ip_restriction_allows_setting_when_current_ip_included(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password, ip="203.0.113.50")

    r = client.patch(
        "/api/v1/auth/me/security/allowed-ips",
        json={"allowed_ips": "203.0.113.50, 198.51.100.0/24"},
        headers={"x-real-ip": "203.0.113.50"},
    )
    assert r.status_code == 200
    assert r.json()["allowed_login_ips"] == "203.0.113.50,198.51.100.0/24"


def test_login_blocked_from_disallowed_ip(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password, ip="203.0.113.50")

    db = SessionLocal()
    admin = db.query(User).filter_by(username="admin").first()
    admin.allowed_login_ips = "203.0.113.50"
    db.add(admin)
    db.commit()
    db.close()

    client.cookies.clear()
    r = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": password},
        headers={"x-real-ip": "198.51.100.99"},
    )
    assert r.status_code == 403


def test_login_succeeds_from_allowed_cidr_range(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password, ip="203.0.113.50")

    db = SessionLocal()
    admin = db.query(User).filter_by(username="admin").first()
    admin.allowed_login_ips = "198.51.100.0/24"
    db.add(admin)
    db.commit()
    db.close()

    client.cookies.clear()
    r = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": password},
        headers={"x-real-ip": "198.51.100.42"},
    )
    assert r.status_code == 200


def test_login_unaffected_when_no_restriction_set(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password, ip="203.0.113.50")

    client.cookies.clear()
    r = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": password},
        headers={"x-real-ip": "1.2.3.4"},
    )
    assert r.status_code == 200


def test_empty_allowed_ips_clears_restriction(client):
    from app.core.db import SessionLocal
    from app.models.user import User

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password, ip="203.0.113.50")

    db = SessionLocal()
    admin = db.query(User).filter_by(username="admin").first()
    admin.allowed_login_ips = "203.0.113.50"
    db.add(admin)
    db.commit()
    db.close()

    r = client.patch(
        "/api/v1/auth/me/security/allowed-ips", json={"allowed_ips": ""},
        headers={"x-real-ip": "203.0.113.50"},
    )
    assert r.status_code == 200
    assert r.json()["allowed_login_ips"] is None


# --- Automatischer Logout / Session-Timeout ---------------------------------

def test_session_timeout_get_returns_global_default_when_unset(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/auth/me/security/session-timeout")
    assert r.status_code == 200
    assert r.json()["session_timeout_minutes"] is None
    assert r.json()["effective_minutes"] > 0


def test_session_timeout_rejects_out_of_range_values(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/auth/me/security/session-timeout", json={"session_timeout_minutes": 1})
    assert r.status_code == 400

    r2 = client.patch("/api/v1/auth/me/security/session-timeout", json={"session_timeout_minutes": 999999})
    assert r2.status_code == 400


def test_session_timeout_accepts_valid_value(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/auth/me/security/session-timeout", json={"session_timeout_minutes": 15})
    assert r.status_code == 200
    assert r.json()["session_timeout_minutes"] == 15
    assert r.json()["effective_minutes"] == 15


def test_session_timeout_reset_to_default_with_null(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    client.patch("/api/v1/auth/me/security/session-timeout", json={"session_timeout_minutes": 15})
    r = client.patch("/api/v1/auth/me/security/session-timeout", json={"session_timeout_minutes": None})
    assert r.json()["session_timeout_minutes"] is None


@pytest.mark.asyncio
async def test_session_ttl_actually_shortened_in_redis(client):
    """Bestaetigt, dass ein individuelles Timeout tatsaechlich auf die
    Redis-Session-TTL angewendet wird (nicht nur in der DB gespeichert)."""
    import app.core.sessions as sessions_module

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.patch("/api/v1/auth/me/security/session-timeout", json={"session_timeout_minutes": 5})

    # Naechste authentifizierte Anfrage soll die TTL auf 5*60=300s setzen
    client.get("/api/v1/auth/me")

    session_id = client.cookies.get("toolbox_session")
    ttl = await sessions_module._redis.ttl(f"session:{session_id}")
    assert 0 < ttl <= 300

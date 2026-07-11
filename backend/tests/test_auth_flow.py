"""Integrationstest fuer den kompletten Auth-Flow: Passwort -> TOTP-Setup ->
Session -> geschuetzte Endpoints -> Logout -> Re-Login -> RBAC.

Nutzt fakeredis (kein echter Redis-Server notwendig) und eine isolierte
SQLite-Datei pro Testlauf (siehe conftest.py fuer die 'client'-Fixture).
"""

import pyotp

from tests.conftest import create_admin as _create_admin


def test_full_login_flow_with_totp_setup(client):
    password = _create_admin()

    # Schritt 1: Passwort
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert r.status_code == 200
    data = r.json()
    assert data["needs_2fa_setup"] is True
    pending_token = data["pending_token"]

    # Geschuetzter Endpoint ist ohne Session gesperrt
    assert client.get("/api/v1/tools").status_code == 401

    # Schritt 2: TOTP-Setup
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    assert r.status_code == 200
    secret = r.json()["secret"]
    assert r.json()["qr_code"].startswith("data:image/png;base64,")

    code = pyotp.TOTP(secret).now()
    r = client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
    assert r.status_code == 200

    # Jetzt authentifiziert
    r = client.get("/api/v1/tools")
    assert r.status_code == 200
    assert len(r.json()) == 72

    me = client.get("/api/v1/auth/me").json()
    assert me["has_2fa"] is True

    # Logout sperrt wieder
    client.post("/api/v1/auth/logout")
    assert client.get("/api/v1/tools").status_code == 401


def test_wrong_password_and_unknown_user_give_identical_error(client):
    password = _create_admin()

    r_wrong = client.post("/api/v1/auth/login", json={"username": "admin", "password": "falsch"})
    r_unknown = client.post("/api/v1/auth/login", json={"username": "no-such-user", "password": "x"})

    assert r_wrong.status_code == 401
    assert r_unknown.status_code == 401
    assert r_wrong.json()["detail"] == r_unknown.json()["detail"]


def test_relogin_with_existing_totp_and_wrong_code_rejected(client):
    password = _create_admin()

    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
    client.post("/api/v1/auth/logout")

    # Zweiter Login: jetzt ist TOTP schon eingerichtet
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    data = r.json()
    assert data["needs_2fa_setup"] is False
    assert data["available_methods"] == ["totp"]

    # Falscher Code wird abgelehnt
    r = client.post(
        "/api/v1/auth/2fa/totp/verify", json={"pending_token": data["pending_token"], "code": "000000"}
    )
    assert r.status_code == 401

    # Richtiger Code funktioniert
    code2 = pyotp.TOTP(secret).now()
    r = client.post(
        "/api/v1/auth/2fa/totp/verify", json={"pending_token": data["pending_token"], "code": code2}
    )
    assert r.status_code == 200


def test_member_cannot_access_admin_user_management(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(
        User(
            username="member1",
            password_hash=hash_password("AuchEinSicheresPW123"),
            role=UserRole.MEMBER.value,
            is_active=True,
        )
    )
    db.commit()
    db.close()

    r = client.post("/api/v1/auth/login", json={"username": "member1", "password": "AuchEinSicheresPW123"})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})

    assert client.get("/api/v1/users").status_code == 403

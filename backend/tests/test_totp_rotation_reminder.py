"""Tests fuer die Secrets-Rotation-Erinnerung: Admins sehen, welche
Konten ihr 2FA-Secret schon sehr lange (>=180 Tage) nicht mehr rotiert
haben.
"""

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


def test_totp_setup_sets_rotation_timestamp(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/users")
    admin_user = next(u for u in r.json() if u["username"] == "admin")
    assert admin_user["totp_rotated_at"] is not None


def test_security_hygiene_flags_stale_totp(client):
    from app.core.db import SessionLocal
    from app.models.user import User
    from datetime import datetime, timedelta, timezone

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    db = SessionLocal()
    admin = db.query(User).filter_by(username="admin").first()
    admin.totp_rotated_at = datetime.now(timezone.utc) - timedelta(days=200)
    db.add(admin)
    db.commit()
    db.close()

    r = client.get("/api/v1/system/security-hygiene")
    assert r.status_code == 200
    stale = r.json()["users_with_stale_totp"]
    assert any(u["username"] == "admin" and u["days_since_rotation"] >= 200 for u in stale)


def test_security_hygiene_does_not_flag_recent_rotation(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/system/security-hygiene")
    stale = r.json()["users_with_stale_totp"]
    assert not any(u["username"] == "admin" for u in stale)


def test_security_hygiene_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.get("/api/v1/system/security-hygiene")
    assert r.status_code == 403

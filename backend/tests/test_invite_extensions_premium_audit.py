"""Tests fuer: Audit-Log, Member-Invite-Selfservice, Premium-Felder,
Appearance-Transparenz/Blur, Feature-Request-CSV-Export, SMTP-Debug und
die requires_admin-Durchsetzung am generischen Tool-Endpoint.
"""

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


def _create_member(username: str, password: str, can_invite: bool = False) -> None:
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    # can_invite=True wird hier auf ein Kontingent von 3 abgebildet (die
    # Tests in dieser Datei pruefen nur "darf ueberhaupt erstellen", nicht
    # die genaue Kontingent-Anzahl -- die hat eine eigene Testdatei).
    db.add(User(
        username=username, password_hash=hash_password(password), role=UserRole.MEMBER.value,
        is_active=True, invite_quota=3 if can_invite else 0,
    ))
    db.commit()
    db.close()


# --- Audit-Log --------------------------------------------------------------

def test_failed_login_creates_audit_entry(client):
    password = _create_admin()
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "falsches-passwort"})
    _login_with_totp_setup(client, "admin", password)

    entries = client.get("/api/v1/system/audit-log").json()
    failed = [e for e in entries if e["event_type"] == "login_password" and not e["success"]]
    assert len(failed) >= 1
    assert failed[0]["username"] == "admin"


def test_successful_login_creates_audit_entry(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    entries = client.get("/api/v1/system/audit-log").json()
    success = [e for e in entries if e["event_type"] == "login_password" and e["success"]]
    assert len(success) >= 1


def test_audit_log_requires_admin(client):
    _create_member("member1", "AuchEinSicheresPW123")
    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.get("/api/v1/system/audit-log")
    assert r.status_code == 403


def test_admin_user_update_creates_audit_entry(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _create_member("bob", "BobsSicheresPasswort1")

    users = client.get("/api/v1/users").json()
    bob = next(u for u in users if u["username"] == "bob")
    client.patch(f"/api/v1/users/{bob['id']}", json={"is_premium": True})

    entries = client.get("/api/v1/system/audit-log").json()
    updates = [e for e in entries if e["event_type"] == "admin_update_user"]
    assert len(updates) >= 1
    assert "bob" in updates[0]["detail"]


# --- Member-Invite-Selfservice ----------------------------------------------

def test_member_without_can_invite_cannot_create_invite(client):
    _create_member("member1", "AuchEinSicheresPW123", can_invite=False)
    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/invites", json={})
    assert r.status_code == 403


def test_member_with_can_invite_can_create_invite_but_only_member_role(client):
    _create_member("member1", "AuchEinSicheresPW123", can_invite=True)
    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")

    # Versucht, einen admin-Invite zu erstellen -- wird stillschweigend auf 'member' erzwungen
    r = client.post("/api/v1/invites", json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "member"


def test_member_sees_only_own_invites_in_mine_endpoint(client):
    password = _create_admin()
    admin_secret = _login_with_totp_setup(client, "admin", password)
    client.post("/api/v1/invites", json={"note": "admin-invite"})

    client.cookies.clear()
    _create_member("member1", "AuchEinSicheresPW123", can_invite=True)
    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    client.post("/api/v1/invites", json={"note": "member-invite"})

    mine = client.get("/api/v1/invites/mine").json()
    assert len(mine) == 1
    assert mine[0]["note"] == "member-invite"


def test_member_can_only_revoke_own_invite(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/invites", json={})
    admin_invite_id = r.json()["id"]

    client.cookies.clear()
    _create_member("member1", "AuchEinSicheresPW123", can_invite=True)
    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")

    r = client.delete(f"/api/v1/invites/{admin_invite_id}")
    assert r.status_code == 403


# --- Premium-Felder ----------------------------------------------------------

def test_user_out_includes_premium_fields(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    users = client.get("/api/v1/users").json()
    assert "is_premium" in users[0]
    assert "premium_badge_color" in users[0]
    assert "invite_quota" in users[0]


def test_admin_can_grant_premium(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _create_member("bob", "BobsSicheresPasswort1")

    users = client.get("/api/v1/users").json()
    bob = next(u for u in users if u["username"] == "bob")
    r = client.patch(f"/api/v1/users/{bob['id']}", json={"is_premium": True, "premium_badge_color": "#FF00FF"})
    assert r.status_code == 200
    assert r.json()["is_premium"] is True
    assert r.json()["premium_badge_color"] == "#FF00FF"


def test_invalid_premium_badge_color_rejected(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    _create_member("bob", "BobsSicheresPasswort1")
    users = client.get("/api/v1/users").json()
    bob = next(u for u in users if u["username"] == "bob")
    r = client.patch(f"/api/v1/users/{bob['id']}", json={"premium_badge_color": "not-a-color"})
    assert r.status_code == 422


# --- Appearance: Transparenz/Blur -------------------------------------------

def test_appearance_transparency_and_blur_roundtrip(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.patch("/api/v1/appearance", json={"background_style": "dots", "form_opacity_percent": 50, "form_blur_px": 12})
    assert r.status_code == 200
    assert r.json()["form_opacity_percent"] == 50
    assert r.json()["form_blur_px"] == 12


def test_appearance_transparency_clamped(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.patch("/api/v1/appearance", json={"background_style": "dots", "form_opacity_percent": 500, "form_blur_px": -5})
    assert r.json()["form_opacity_percent"] == 100
    assert r.json()["form_blur_px"] == 0


# --- Feature-Request CSV-Export ---------------------------------------------

def test_feature_request_csv_export(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.post("/api/v1/feature-requests", json={"title": "CSV Test", "description": "Beschreibung"})

    r = client.get("/api/v1/feature-requests/export.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "CSV Test" in r.text
    assert "id,title,description" in r.text


# --- SMTP Debug: requires_admin ----------------------------------------------

def test_smtp_debug_requires_admin(client):
    _create_member("member1", "AuchEinSicheresPW123")
    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/smtp-debug", json={
        "host": "example.com", "mail_from": "test@example.com", "rcpt_to": ["ziel@example.com"],
    })
    assert r.status_code == 403


def test_smtp_debug_input_validation():
    from app.modules.mail.smtp_debug import SmtpDebugModule

    with pytest.raises(ValidationError):
        SmtpDebugModule.Input(host="example.com", mail_from="not-an-email", rcpt_to=["ziel@example.com"])

    with pytest.raises(ValidationError):
        SmtpDebugModule.Input(host="example.com", mail_from="test@example.com", rcpt_to=[])

    with pytest.raises(ValidationError):
        SmtpDebugModule.Input(
            host="example.com", mail_from="test@example.com",
            rcpt_to=[f"r{i}@example.com" for i in range(10)],
        )


def test_all_new_modules_registered():
    from app.modules import get_registry

    registry = get_registry()
    assert "smtp-debug" in registry
    assert registry["smtp-debug"].requires_admin is True
    assert "dkim-signature-inspector" in registry

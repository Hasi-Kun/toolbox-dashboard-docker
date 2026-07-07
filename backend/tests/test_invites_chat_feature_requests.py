"""Tests fuer Invite-Registrierung, Shoutbox, Feature-Request-Board und den
DKIM-Signature-Inspector. Diverse echte Bugs wurden hier beim manuellen
Testen gefunden und gefixt (siehe Kommentare in den jeweiligen Modulen):
ein durch einen fehlerhaften str_replace verschmolzenes Datenmodell
(InviteCode/ChatMessage), und ein SQLite-Timezone-Vergleichsfehler.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pyotp
import pytest
from pydantic import ValidationError

from app.models.user import InviteCode
from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> str:
    """Gibt das TOTP-Secret zurueck, damit spaeter erneut eingeloggt werden kann."""
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
    return secret


def _login_with_existing_totp(client, username: str, password: str, secret: str) -> None:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/verify", json={"pending_token": pending_token, "code": code})


# --- Invite-Registrierung ------------------------------------------------

def test_full_invite_register_flow(client):
    password = _create_admin()
    admin_secret = _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/invites", json={"note": "fuer Bob", "role": "member", "expires_in_days": 7})
    assert r.status_code == 200
    invite_code = r.json()["code"]

    client.cookies.clear()
    r = client.post("/api/v1/auth/register", json={"invite_code": invite_code, "username": "bob", "password": "BobsSicheresPW123"})
    assert r.status_code == 200
    assert r.json()["needs_2fa_setup"] is True

    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    r = client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})
    assert r.status_code == 200

    r = client.post("/api/v1/auth/login", json={"username": "bob", "password": "BobsSicheresPW123"})
    assert r.status_code == 200
    assert r.json()["needs_2fa_setup"] is False


def test_invite_cannot_be_used_twice(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/invites", json={})
    invite_code = r.json()["code"]

    client.cookies.clear()
    client.post("/api/v1/auth/register", json={"invite_code": invite_code, "username": "first", "password": "ErstesSicheresPW12"})

    r = client.post("/api/v1/auth/register", json={"invite_code": invite_code, "username": "second", "password": "ZweitesSicheresPW1"})
    assert r.status_code == 400


def test_invalid_invite_code_rejected(client):
    r = client.post("/api/v1/auth/register", json={"invite_code": "does-not-exist", "username": "eve", "password": "EvesSicheresPW1234"})
    assert r.status_code == 400


def test_expired_invite_code_rejected(client):
    """Regressionstest fuer den SQLite-Timezone-Vergleichsfehler: naive
    datetimes aus der DB muessen als UTC interpretiert werden, bevor sie
    mit einem timezone-aware 'jetzt' verglichen werden."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/invites", json={"expires_in_days": 1})
    code = r.json()["code"]

    from app.core.db import SessionLocal

    db = SessionLocal()
    invite = db.query(InviteCode).filter(InviteCode.code == code).first()
    invite.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.add(invite)
    db.commit()
    db.close()

    client.cookies.clear()
    r = client.post("/api/v1/auth/register", json={"invite_code": code, "username": "late", "password": "ZuSpaetSicheresPW1"})
    assert r.status_code == 400
    assert "abgelaufen" in r.json()["detail"]


def test_member_cannot_create_invite(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/invites", json={})
    assert r.status_code == 403


def test_unused_invite_can_be_revoked(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/invites", json={})
    unused_id = r.json()["id"]
    r = client.delete(f"/api/v1/invites/{unused_id}")
    assert r.status_code == 200

    assert client.get("/api/v1/invites").json() == []


def test_used_invite_cannot_be_revoked(client):
    password = _create_admin()
    admin_secret = _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/invites", json={})
    used_code = r.json()["code"]
    used_id = r.json()["id"]

    client.cookies.clear()
    client.post("/api/v1/auth/register", json={"invite_code": used_code, "username": "someone", "password": "SomeonesSicheresPW"})

    client.cookies.clear()
    _login_with_existing_totp(client, "admin", password, admin_secret)
    r = client.delete(f"/api/v1/invites/{used_id}")
    assert r.status_code == 400


# --- Shoutbox -------------------------------------------------------------

def test_chat_post_and_list(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/chat/messages", json={"message": "Hallo Welt"})
    assert r.status_code == 200
    assert r.json()["is_own"] is True

    messages = client.get("/api/v1/chat/messages").json()
    assert len(messages) == 1
    assert messages[0]["message"] == "Hallo Welt"


def test_chat_rejects_empty_message(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/chat/messages", json={"message": "   "})
    assert r.status_code == 422


def test_chat_rejects_too_long_message(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/chat/messages", json={"message": "x" * 501})
    assert r.status_code == 422


def test_chat_delete_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    client.post("/api/v1/chat/messages", json={"message": "Test"})
    msg_id = client.get("/api/v1/chat/messages").json()[0]["id"]

    r = client.delete(f"/api/v1/chat/messages/{msg_id}")
    assert r.status_code == 403


def test_chat_requires_auth(client):
    r = client.get("/api/v1/chat/messages")
    assert r.status_code == 401


# --- Feature Requests -------------------------------------------------------

def test_feature_request_create_and_vote(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/feature-requests", json={"title": "Dark Mode", "description": "Waere schoen"})
    assert r.status_code == 200
    req_id = r.json()["id"]
    assert r.json()["score"] == 0

    r = client.post(f"/api/v1/feature-requests/{req_id}/vote", json={"direction": "up"})
    assert r.json() == {"user_vote": 1, "score": 1, "upvotes": 1, "downvotes": 0}

    # Erneuter Klick entfernt die Stimme wieder (Toggle)
    r = client.post(f"/api/v1/feature-requests/{req_id}/vote", json={"direction": "up"})
    assert r.json() == {"user_vote": 0, "score": 0, "upvotes": 0, "downvotes": 0}


def test_feature_request_downvote(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y"})
    req_id = r.json()["id"]

    r = client.post(f"/api/v1/feature-requests/{req_id}/vote", json={"direction": "down"})
    assert r.json() == {"user_vote": -1, "score": -1, "upvotes": 0, "downvotes": 1}

    # Wechsel von Down- zu Upvote
    r = client.post(f"/api/v1/feature-requests/{req_id}/vote", json={"direction": "up"})
    assert r.json() == {"user_vote": 1, "score": 1, "upvotes": 1, "downvotes": 0}


def test_feature_request_comments_and_detail(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y"})
    req_id = r.json()["id"]

    client.post(f"/api/v1/feature-requests/{req_id}/comments", json={"comment": "Gute Idee!"})
    detail = client.get(f"/api/v1/feature-requests/{req_id}").json()
    assert len(detail["comments"]) == 1
    assert detail["comments"][0]["comment"] == "Gute Idee!"


def test_feature_request_sorted_by_votes(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r1 = client.post("/api/v1/feature-requests", json={"title": "Wenig Stimmen", "description": "x"})
    r2 = client.post("/api/v1/feature-requests", json={"title": "Viele Stimmen", "description": "x"})
    id2 = r2.json()["id"]

    client.post(f"/api/v1/feature-requests/{id2}/vote", json={"direction": "up"})

    listing = client.get("/api/v1/feature-requests").json()["items"]
    assert listing[0]["title"] == "Viele Stimmen"


def test_feature_request_status_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y"})
    req_id = r.json()["id"]

    r = client.patch(f"/api/v1/feature-requests/{req_id}/status", json={"status": "planned"})
    assert r.status_code == 403


def test_feature_request_status_rejects_invalid_value(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y"})
    req_id = r.json()["id"]

    r = client.patch(f"/api/v1/feature-requests/{req_id}/status", json={"status": "not-a-real-status"})
    assert r.status_code == 422


def test_own_comment_deletable_others_not(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.add(User(username="member2", password_hash=hash_password("AuchEinSicheresPW456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    member1_secret = _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/feature-requests", json={"title": "X", "description": "Y"})
    req_id = r.json()["id"]
    r = client.post(f"/api/v1/feature-requests/{req_id}/comments", json={"comment": "von member1"})
    own_comment_id = r.json()["id"]

    r = client.delete(f"/api/v1/feature-requests/{req_id}/comments/{own_comment_id}")
    assert r.status_code == 200

    client.cookies.clear()
    _login_with_totp_setup(client, "member2", "AuchEinSicheresPW456")
    r = client.post(f"/api/v1/feature-requests/{req_id}/comments", json={"comment": "von member2"})
    other_comment_id = r.json()["id"]

    client.cookies.clear()
    _login_with_existing_totp(client, "member1", "AuchEinSicheresPW123", member1_secret)
    r = client.delete(f"/api/v1/feature-requests/{req_id}/comments/{other_comment_id}")
    assert r.status_code == 403


# --- DKIM Signature Inspector ----------------------------------------------

def test_dkim_signature_inspector_rejects_empty_header():
    from app.modules.mail.dkim_signature_inspector import DkimSignatureInspectorModule

    with pytest.raises(ValidationError):
        DkimSignatureInspectorModule.Input(dkim_signature_header="   ")


@pytest.mark.asyncio
async def test_dkim_signature_inspector_parses_header_fields():
    import base64
    import os

    from app.modules.mail.dkim_signature_inspector import DkimSignatureInspectorModule

    fake_bh = base64.b64encode(os.urandom(32)).decode()
    fake_b = base64.b64encode(os.urandom(256)).decode()
    header = f"v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20161025; h=from:to:subject; bh={fake_bh}; b={fake_b}"

    result = await DkimSignatureInspectorModule().run(DkimSignatureInspectorModule.Input(dkim_signature_header=header))

    assert result.parsed.domain == "gmail.com"
    assert result.parsed.selector == "20161025"
    assert result.parsed.algorithm == "rsa-sha256"
    assert result.parsed.signed_headers == ["from", "to", "subject"]
    assert any("Body-Hash-Laenge passt" in f for f in result.findings)


@pytest.mark.asyncio
async def test_dkim_signature_inspector_detects_expired_signature():
    import time

    from app.modules.mail.dkim_signature_inspector import DkimSignatureInspectorModule

    past_timestamp = int(time.time()) - 100000
    header = f"v=1; a=rsa-sha256; d=example.com; s=default; x={past_timestamp}"

    result = await DkimSignatureInspectorModule().run(DkimSignatureInspectorModule.Input(dkim_signature_header=header))
    assert any("abgelaufen" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_dkim_signature_inspector_rejects_malformed_header():
    from app.modules.mail.dkim_signature_inspector import DkimSignatureInspectorModule

    result = await DkimSignatureInspectorModule().run(
        DkimSignatureInspectorModule.Input(dkim_signature_header="this is not a dkim header at all")
    )
    assert result.dns_key_found is False
    assert result.error is not None


# --- Online-Users-Zaehler ----------------------------------------------------

def test_online_users_counter(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/system/online-users")
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["usernames"] == ["admin"]


def test_online_users_requires_auth(client):
    r = client.get("/api/v1/system/online-users")
    assert r.status_code == 401

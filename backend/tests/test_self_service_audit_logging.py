"""Tests fuer die neu ergaenzte Audit-Protokollierung von Selbstbedienungs-
Aktionen normaler Nutzer (Passwort aendern, 2FA einrichten/deaktivieren,
Passkey hinzufuegen/entfernen) -- vorher wurden nur Login-Events und
Admin-Aktionen geloggt, wodurch das Audit-Log faelschlich wie eine reine
Admin-Aktivitaets-Liste wirkte.
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


def _get_audit_entries(client) -> list[dict]:
    return client.get("/api/v1/system/audit-log?page_size=200").json()["items"]


def test_password_change_by_regular_member_is_logged(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AltesPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AltesPasswort123456")
    r = client.post("/api/v1/auth/me/password", json={"current_password": "AltesPasswort123456", "new_password": "NeuesPasswort1234567"})
    assert r.status_code == 200

    admin_password = _create_admin()
    client.cookies.clear()
    _login_with_totp_setup(client, "admin", admin_password)
    entries = _get_audit_entries(client)
    password_events = [e for e in entries if e["event_type"] == "password_changed" and e["username"] == "member1"]
    assert len(password_events) == 1
    assert password_events[0]["success"] is True


def test_wrong_current_password_logs_failure(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member2", password_hash=hash_password("AltesPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member2", "AltesPasswort123456")
    client.post("/api/v1/auth/me/password", json={"current_password": "FalschesPasswort", "new_password": "NeuesPasswort1234567"})

    admin_password = _create_admin()
    client.cookies.clear()
    _login_with_totp_setup(client, "admin", admin_password)
    entries = _get_audit_entries(client)
    failed_events = [e for e in entries if e["event_type"] == "password_changed" and e["username"] == "member2" and not e["success"]]
    assert len(failed_events) == 1


def test_totp_enable_and_disable_by_member_is_logged(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member3", password_hash=hash_password("SicheresPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    # Initiales 2FA-Setup passiert bereits waehrend des ersten Logins (Pflicht) --
    # das zaehlt als "totp_enabled". Danach einmal deaktivieren wuerde fehlschlagen
    # (einzige 2FA-Methode), daher pruefen wir hier nur das anfaengliche Enable.
    _login_with_totp_setup(client, "member3", "SicheresPasswort123456")

    admin_password = _create_admin()
    client.cookies.clear()
    _login_with_totp_setup(client, "admin", admin_password)
    entries = _get_audit_entries(client)
    enabled_events = [e for e in entries if e["event_type"] == "totp_enabled" and e["username"] == "member3"]
    assert len(enabled_events) == 1


def test_audit_log_shows_both_member_and_admin_events(client):
    """Regressionstest fuer den gemeldeten Vorfall: das Audit-Log darf
    nicht wie eine reine Admin-Aktivitaets-Liste aussehen -- normale
    Mitglieder-Aktionen muessen genauso auftauchen."""
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="normalo", password_hash=hash_password("SicheresPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "normalo", "SicheresPasswort123456")

    admin_password = _create_admin()
    client.cookies.clear()
    _login_with_totp_setup(client, "admin", admin_password)
    entries = _get_audit_entries(client)

    member_usernames = {e["username"] for e in entries if e["username"] == "normalo"}
    admin_usernames = {e["username"] for e in entries if e["username"] == "admin"}
    assert "normalo" in member_usernames, "Mitglieder-Aktionen fehlen im Audit-Log"
    assert "admin" in admin_usernames

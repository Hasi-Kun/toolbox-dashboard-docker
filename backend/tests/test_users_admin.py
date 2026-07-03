"""Tests fuer die Admin-Benutzerverwaltung (/api/v1/users)."""

import pyotp

from tests.conftest import create_admin as _create_admin


def _login_and_complete_totp(client, username: str, password: str, existing_secret: str | None = None) -> str:
    """Fuehrt einen vollstaendigen Login durch. Beim ersten Aufruf (kein
    existing_secret) wird TOTP frisch eingerichtet; das Secret wird
    zurueckgegeben, damit spaetere Re-Logins im selben Test es wiederverwenden
    koennen.
    """
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    data = r.json()
    pending_token = data["pending_token"]

    if data["needs_2fa_setup"]:
        r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
        secret = r.json()["secret"]
        code = pyotp.TOTP(secret).now()
        client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})
        return secret

    assert existing_secret is not None, "Account hat schon 2FA, aber kein existing_secret uebergeben"
    code = pyotp.TOTP(existing_secret).now()
    client.post("/api/v1/auth/2fa/totp/verify", json={"pending_token": pending_token, "code": code})
    return existing_secret


def test_admin_can_create_list_and_manage_users(client):
    password = _create_admin()
    admin_secret = _login_and_complete_totp(client, "admin", password)

    # Neuen Member-User anlegen, ohne Passwort -> Server generiert eins
    r = client.post("/api/v1/users", json={"username": "bob", "role": "member"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["username"] == "bob"
    assert body["user"]["role"] == "member"
    assert body["generated_password"] is not None
    bob_id = body["user"]["id"]

    # Liste enthaelt jetzt admin + bob
    r = client.get("/api/v1/users")
    usernames = {u["username"] for u in r.json()}
    assert usernames == {"admin", "bob"}

    # Doppelter Username wird abgelehnt
    r = client.post("/api/v1/users", json={"username": "bob"})
    assert r.status_code == 409

    # Admin befoerdert bob zu admin
    r = client.patch(f"/api/v1/users/{bob_id}", json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"

    # Admin deaktiviert bob
    r = client.patch(f"/api/v1/users/{bob_id}", json={"is_active": False})
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    # Admin kann sich nicht selbst deaktivieren
    me = client.get("/api/v1/auth/me").json()
    r = client.patch(f"/api/v1/users/{me['id']}", json={"is_active": False})
    assert r.status_code == 400

    # Admin kann sich nicht selbst loeschen
    r = client.delete(f"/api/v1/users/{me['id']}")
    assert r.status_code == 400

    # Aber bob loeschen geht
    r = client.delete(f"/api/v1/users/{bob_id}")
    assert r.status_code == 200
    r = client.get("/api/v1/users")
    assert len(r.json()) == 1


def test_reset_2fa_forces_reenrollment(client):
    password = _create_admin()
    admin_secret = _login_and_complete_totp(client, "admin", password)

    r = client.post("/api/v1/users", json={"username": "carol", "password": "EinStarkesPasswort123"})
    carol_id = r.json()["user"]["id"]

    client.cookies.clear()
    _login_and_complete_totp(client, "carol", "EinStarkesPasswort123")

    me = client.get("/api/v1/auth/me").json()
    assert me["has_2fa"] is True

    # Zurueck zum Admin (bereits eingerichtetes TOTP wiederverwenden), 2FA von carol zuruecksetzen
    client.cookies.clear()
    _login_and_complete_totp(client, "admin", password, existing_secret=admin_secret)
    r = client.post(f"/api/v1/users/{carol_id}/reset-2fa")
    assert r.status_code == 200
    assert r.json()["has_2fa"] is False

    # Carol muss sich jetzt erneut fuer 2FA einrichten
    client.cookies.clear()
    r = client.post("/api/v1/auth/login", json={"username": "carol", "password": "EinStarkesPasswort123"})
    assert r.json()["needs_2fa_setup"] is True

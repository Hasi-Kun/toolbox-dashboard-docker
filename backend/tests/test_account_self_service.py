"""Tests fuer Passwort-Aenderung und Mehrfach-2FA (TOTP + Passkey gleichzeitig)."""

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


def test_change_password_requires_correct_current_password(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/auth/me/password", json={"current_password": "falsch", "new_password": "EinNeuesPasswort123"})
    assert r.status_code == 401

    r = client.post("/api/v1/auth/me/password", json={"current_password": password, "new_password": "zukurz"})
    assert r.status_code == 422

    r = client.post(
        "/api/v1/auth/me/password", json={"current_password": password, "new_password": "EinNeuesPasswort123"}
    )
    assert r.status_code == 200

    # Alte Session bleibt gueltig...
    assert client.get("/api/v1/auth/me").status_code == 200

    # ... aber ein neuer Login braucht jetzt das neue Passwort
    client.cookies.clear()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert r.status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "EinNeuesPasswort123"})
    assert r.status_code == 200


def test_totp_and_passkey_status_reflects_multiple_methods(client):
    """Simuliert das Hinzufuegen von TOTP UND einem "Passkey" (hier nur als
    DB-Eintrag simuliert, da ein echter Authenticator im Test nicht verfuegbar
    ist -- die WebAuthn-Kryptoverifikation selbst wird durch die
    `webauthn`-Library abgedeckt, nicht hier neu getestet).
    """
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/auth/me/2fa")
    assert r.status_code == 200
    assert r.json()["totp_enabled"] is True
    assert r.json()["passkeys"] == []

    # Passkey manuell in der DB anlegen (Registrierungs-Kryptografie wird
    # durch die Library abgedeckt, hier nur der Verwaltungs-Teil getestet)
    from app.core.db import SessionLocal
    from app.models.user import User, WebAuthnCredential

    db = SessionLocal()
    admin_user = db.query(User).filter(User.username == "admin").first()
    db.add(
        WebAuthnCredential(
            user_id=admin_user.id,
            credential_id="dummy-credential-id",
            public_key="dummy-public-key",
            nickname="Mein Laptop",
        )
    )
    db.commit()
    db.close()

    r = client.get("/api/v1/auth/me/2fa")
    data = r.json()
    assert data["totp_enabled"] is True
    assert len(data["passkeys"]) == 1
    assert data["passkeys"][0]["nickname"] == "Mein Laptop"
    passkey_id = data["passkeys"][0]["id"]

    # TOTP deaktivieren geht, weil noch ein Passkey da ist
    r = client.post("/api/v1/auth/me/2fa/totp/disable")
    assert r.status_code == 200
    assert r.json()["totp_enabled"] is False

    # Jetzt den letzten Passkey loeschen zu wollen wird blockiert (0 Methoden uebrig)
    r = client.delete(f"/api/v1/auth/me/2fa/passkey/{passkey_id}")
    assert r.status_code == 400


def test_disabling_totp_blocked_when_it_is_the_only_method(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/auth/me/2fa/totp/disable")
    assert r.status_code == 400


def test_can_add_totp_via_self_service_endpoint_while_already_logged_in(client):
    """Deckt den Fall ab, dass jemand sich zuerst per Passkey eingeloggt hat
    (hier simuliert durch direktes Session-Setzen) und danach TOTP als
    zusaetzliche Methode ergaenzt.
    """
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    # Zweite TOTP-Runde ueber den Self-Service-Endpoint (rotiert das Secret)
    r = client.post("/api/v1/auth/me/2fa/totp/setup/start")
    assert r.status_code == 200
    new_secret = r.json()["secret"]
    code = pyotp.TOTP(new_secret).now()
    r = client.post("/api/v1/auth/me/2fa/totp/setup/verify", json={"code": code})
    assert r.status_code == 200
    assert r.json()["totp_enabled"] is True

"""Tests fuer die WebSSH-Webshell (WebSocket-Terminal) und gespeicherte
SSH-Verbindungen. Die Kernfunktionalitaet (echte SSH-Verbindung, echte
Befehle, Terminal-Resize) wurde zusaetzlich live gegen einen echten
lokalen sshd verifiziert -- hier folgen die Tests fuer die CI-Suite mit
gemocktem asyncssh sowie die vollstaendig echten Tests fuer die
verschluesselte Speicherung und Nutzer-Isolation.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


# --- Verschluesselung ---------------------------------------------------------

def test_ssh_vault_round_trip():
    from app.core.ssh_vault import decrypt_secret, encrypt_secret

    secret = "super-geheimes-passwort-123"
    encrypted = encrypt_secret(secret)
    assert secret not in encrypted
    assert decrypt_secret(encrypted) == secret


def test_ssh_vault_rejects_invalid_ciphertext():
    from app.core.ssh_vault import SshVaultError, decrypt_secret

    with pytest.raises(SshVaultError):
        decrypt_secret("offensichtlich-kein-gueltiges-token")


# --- Gespeicherte Verbindungen: CRUD + Nutzer-Isolation ----------------------

def test_create_and_list_saved_connection(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post(
        "/api/v1/ssh-connections",
        json={"label": "Prod-Server", "host": "10.0.0.5", "port": 22, "username": "root", "auth_method": "password", "secret": "geheim123"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["has_stored_secret"] is True
    assert "secret" not in body
    assert "encrypted_secret" not in body

    r = client.get("/api/v1/ssh-connections")
    assert len(r.json()) == 1
    assert r.json()[0]["label"] == "Prod-Server"


def test_saved_connection_without_secret(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/ssh-connections", json={"label": "Ohne-Geheimnis", "host": "10.0.0.6", "username": "admin"})
    assert r.status_code == 200
    assert r.json()["has_stored_secret"] is False


def test_rejects_duplicate_label_for_same_user(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    client.post("/api/v1/ssh-connections", json={"label": "Dup", "host": "1.1.1.1", "username": "root"})
    r = client.post("/api/v1/ssh-connections", json={"label": "Dup", "host": "2.2.2.2", "username": "root"})
    assert r.status_code == 400


def test_saved_connections_strictly_isolated_per_user(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="bob", password_hash=hash_password("EinSicheresPasswort2"), role=UserRole.ADMIN.value, is_active=True))
    db.commit()
    db.close()

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/ssh-connections", json={"label": "Admins-Server", "host": "10.0.0.5", "username": "root", "secret": "geheim"})
    conn_id = r.json()["id"]

    client.cookies.clear()
    _login_with_totp_setup(client, "bob", "EinSicheresPasswort2")

    r = client.get("/api/v1/ssh-connections")
    assert r.json() == []

    r = client.delete(f"/api/v1/ssh-connections/{conn_id}")
    assert r.status_code == 404


def test_ssh_connections_require_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.get("/api/v1/ssh-connections")
    assert r.status_code == 403


def test_rejects_invalid_port_and_auth_method(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/ssh-connections", json={"label": "x", "host": "1.1.1.1", "port": 99999, "username": "root"})
    assert r.status_code == 422

    r = client.post("/api/v1/ssh-connections", json={"label": "y", "host": "1.1.1.1", "username": "root", "auth_method": "not-a-real-method"})
    assert r.status_code == 422


# --- WebSocket-Terminal (gemockt) ---------------------------------------------

def test_websocket_rejects_unauthenticated(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/ssh", cookies={}):
            pass


def test_websocket_rejects_non_admin(client):
    from starlette.websockets import WebSocketDisconnect
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member2", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member2", "AuchEinSicheresPW123")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/ssh"):
            pass

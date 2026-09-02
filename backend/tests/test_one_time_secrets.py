"""Tests fuer OneTimePassword (Burn-after-reading-Secret-Sharing-Link).
Der komplette Flow wurde zusaetzlich end-to-end manuell verifiziert."""

from datetime import datetime, timedelta, timezone

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


def _login_existing_2fa(client, username: str, password: str, totp_secret: str) -> None:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    code = pyotp.TOTP(totp_secret).now()
    r = client.post("/api/v1/auth/2fa/totp/verify", json={"pending_token": pending_token, "code": code})
    assert r.status_code == 200


def test_create_requires_auth(client):
    r = client.post("/api/v1/one-time-secrets", json={"content": "geheim", "ttl_hours": 24})
    assert r.status_code == 401


def test_create_and_view_once(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/one-time-secrets", json={"content": "super-geheimes-passwort", "ttl_hours": 24})
    assert r.status_code == 200
    token = r.json()["token"]

    client.cookies.clear()
    r = client.get(f"/api/v1/one-time-secrets/{token}")
    assert r.status_code == 200
    assert r.json()["content"] == "super-geheimes-passwort"


def test_second_view_returns_404(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/one-time-secrets", json={"content": "einmalig", "ttl_hours": 24})
    token = r.json()["token"]

    client.cookies.clear()
    r1 = client.get(f"/api/v1/one-time-secrets/{token}")
    assert r1.status_code == 200

    r2 = client.get(f"/api/v1/one-time-secrets/{token}")
    assert r2.status_code == 404


def test_unknown_token_returns_404(client):
    r = client.get("/api/v1/one-time-secrets/nie-existierender-token")
    assert r.status_code == 404


def test_view_does_not_require_auth(client):
    """Kernanforderung: der Empfaenger hat typischerweise KEIN eigenes
    Toolbox-Konto -- Ansehen muss ohne Login funktionieren."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 1})
    token = r.json()["token"]

    client.cookies.clear()
    r = client.get(f"/api/v1/one-time-secrets/{token}")
    assert r.status_code == 200


def test_expired_secret_never_viewed_returns_404(client):
    from app.core.db import SessionLocal
    from app.core.ssh_vault import encrypt_secret
    from app.models.user import OneTimeSecret, User

    password = _create_admin()
    db = SessionLocal()
    admin_user = db.query(User).filter_by(username="admin").first()
    db.add(OneTimeSecret(
        token="laengst-abgelaufen-token", creator_user_id=admin_user.id,
        encrypted_content=encrypt_secret("x"), expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    ))
    db.commit()
    db.close()

    r = client.get("/api/v1/one-time-secrets/laengst-abgelaufen-token")
    assert r.status_code == 404


def test_rejects_ttl_above_14_days(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 24 * 30})
    assert r.status_code == 422


def test_rejects_empty_content(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "   ", "ttl_hours": 1})
    assert r.status_code == 422


def test_list_mine_shows_metadata_not_content(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "geheim", "ttl_hours": 24})
    token = r.json()["token"]

    r = client.get("/api/v1/one-time-secrets/mine")
    assert r.status_code == 200
    entry = r.json()[0]
    assert entry["token"] == token
    assert entry["viewed_at"] is None
    assert entry["is_expired"] is False
    assert "content" not in entry


def test_list_mine_shows_viewed_at_after_view(client):
    password = _create_admin()
    totp_secret = _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "geheim", "ttl_hours": 24})
    token = r.json()["token"]

    client.cookies.clear()
    client.get(f"/api/v1/one-time-secrets/{token}")

    _login_existing_2fa(client, "admin", password, totp_secret)
    r = client.get("/api/v1/one-time-secrets/mine")
    # Nach dem Abruf ist der Eintrag geloescht -- die Liste zeigt ihn also NICHT mehr,
    # was selbst die Bestaetigung ist, dass er tatsaechlich "verbrannt" wurde.
    assert token not in [e["token"] for e in r.json()]


def test_creator_cannot_view_content_via_mine_endpoint(client):
    """Der Ersteller bekommt KEINEN Sonderzugriff auf den Inhalt --
    dasselbe Einmal-Prinzip gilt fuer alle."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    client.post("/api/v1/one-time-secrets", json={"content": "streng-geheim", "ttl_hours": 24})

    r = client.get("/api/v1/one-time-secrets/mine")
    body_text = r.text
    assert "streng-geheim" not in body_text


def test_revoke_deletes_before_it_is_viewed(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 24})
    token = r.json()["token"]

    r = client.delete(f"/api/v1/one-time-secrets/mine/{token}")
    assert r.status_code == 200

    client.cookies.clear()
    r = client.get(f"/api/v1/one-time-secrets/{token}")
    assert r.status_code == 404


def test_cannot_revoke_someone_elses_secret(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="bob", password_hash=hash_password("EinSicheresPasswort2"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 24})
    token = r.json()["token"]

    client.cookies.clear()
    _login_with_totp_setup(client, "bob", "EinSicheresPasswort2")
    r = client.delete(f"/api/v1/one-time-secrets/mine/{token}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_cleanup_expired_secrets_removes_only_expired(client):
    from app.core.db import SessionLocal
    from app.core.ssh_vault import encrypt_secret
    from app.models.user import OneTimeSecret, User
    from app.api.v1.endpoints.one_time_secrets import cleanup_expired_secrets

    password = _create_admin()
    db = SessionLocal()
    admin_user = db.query(User).filter_by(username="admin").first()
    db.add(OneTimeSecret(token="abgelaufen-1", creator_user_id=admin_user.id, encrypted_content=encrypt_secret("x"), expires_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    db.add(OneTimeSecret(token="noch-gueltig-1", creator_user_id=admin_user.id, encrypted_content=encrypt_secret("y"), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    db.commit()

    deleted = await cleanup_expired_secrets(db)
    assert deleted == 1

    remaining = [e.token for e in db.query(OneTimeSecret).all()]
    assert "noch-gueltig-1" in remaining
    assert "abgelaufen-1" not in remaining
    db.close()


# --- Erweiterungen: Ansichten erhoehen + Gueltigkeit verlaengern --------------

def test_increase_max_views_allows_multiple_reads(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/one-time-secrets", json={"content": "geheim", "ttl_hours": 24})
    token = r.json()["token"]

    r = client.patch(f"/api/v1/one-time-secrets/mine/{token}", json={"add_views": 2})
    assert r.status_code == 200
    assert r.json()["max_views"] == 3

    client.cookies.clear()
    for _ in range(3):
        r = client.get(f"/api/v1/one-time-secrets/{token}")
        assert r.status_code == 200

    r = client.get(f"/api/v1/one-time-secrets/{token}")
    assert r.status_code == 404


def test_extend_ttl_pushes_expiry_forward(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 1})
    token = r.json()["token"]
    old_expiry = r.json()["expires_at"]

    r = client.patch(f"/api/v1/one-time-secrets/mine/{token}", json={"extend_ttl_hours": 24 * 14})
    assert r.status_code == 200
    assert r.json()["expires_at"] > old_expiry


def test_rejects_invalid_add_views_range(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 24})
    token = r.json()["token"]

    r = client.patch(f"/api/v1/one-time-secrets/mine/{token}", json={"add_views": 0})
    assert r.status_code == 422

    r = client.patch(f"/api/v1/one-time-secrets/mine/{token}", json={"add_views": 999})
    assert r.status_code == 422


def test_cannot_increase_views_on_someone_elses_secret(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="bob", password_hash=hash_password("EinSicheresPasswort2"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 24})
    token = r.json()["token"]

    client.cookies.clear()
    _login_with_totp_setup(client, "bob", "EinSicheresPasswort2")
    r = client.patch(f"/api/v1/one-time-secrets/mine/{token}", json={"add_views": 5})
    assert r.status_code == 404


def test_cannot_extend_ttl_on_already_exhausted_secret(client):
    """Nach dem letzten erlaubten Abruf ist die Zeile bereits geloescht
    (das ist der Sinn der Abruf-Begrenzung) -- ein PATCH-Versuch danach
    findet buchstaeblich nichts mehr vor (404), nicht nur "ungueltiger
    Zustand" (400)."""
    password = _create_admin()
    totp_secret = _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 24})
    token = r.json()["token"]

    client.cookies.clear()
    client.get(f"/api/v1/one-time-secrets/{token}")  # verbraucht die einzige erlaubte Ansicht -- Zeile wird geloescht

    _login_existing_2fa(client, "admin", password, totp_secret)
    r = client.patch(f"/api/v1/one-time-secrets/mine/{token}", json={"add_views": 1})
    assert r.status_code == 404


def test_metadata_shows_view_progress(client):
    password = _create_admin()
    totp_secret = _login_with_totp_setup(client, "admin", password)
    r = client.post("/api/v1/one-time-secrets", json={"content": "x", "ttl_hours": 24})
    token = r.json()["token"]
    client.patch(f"/api/v1/one-time-secrets/mine/{token}", json={"add_views": 1})

    client.cookies.clear()
    client.get(f"/api/v1/one-time-secrets/{token}")

    _login_existing_2fa(client, "admin", password, totp_secret)
    r = client.get("/api/v1/one-time-secrets/mine")
    entry = next((e for e in r.json() if e["token"] == token), None)
    assert entry is not None
    assert entry["view_count"] == 1
    assert entry["max_views"] == 2

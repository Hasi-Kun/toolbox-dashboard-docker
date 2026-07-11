"""Tests fuer die Konto-Sperre bei fehlgeschlagenen Login-Versuchen
(zusaetzlich zum bestehenden IP-basierten Rate-Limit) -- schuetzt gegen
Brute-Force mit rotierenden IPs, das das reine IP-Limit sonst umgehen
koennte.
"""

from tests.conftest import create_admin as _create_admin


def test_account_lockout_triggers_regardless_of_ip(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="opfer", password_hash=hash_password("RichtigesPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    statuses = []
    for i in range(12):
        r = client.post(
            "/api/v1/auth/login",
            json={"username": "opfer", "password": f"falsch{i}"},
            headers={"x-real-ip": f"203.0.113.{i}"},
        )
        statuses.append(r.status_code)

    assert statuses[:10] == [401] * 10
    assert 429 in statuses[10:]


def test_account_lockout_blocks_even_correct_password_while_locked(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="opfer2", password_hash=hash_password("RichtigesPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    for i in range(10):
        client.post("/api/v1/auth/login", json={"username": "opfer2", "password": f"falsch{i}"}, headers={"x-real-ip": f"203.0.113.{i}"})

    r = client.post("/api/v1/auth/login", json={"username": "opfer2", "password": "RichtigesPasswort123456"}, headers={"x-real-ip": "203.0.113.99"})
    assert r.status_code == 429


def test_successful_login_resets_failed_attempt_counter(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="normalo", password_hash=hash_password("RichtigesPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    for i in range(3):
        client.post("/api/v1/auth/login", json={"username": "normalo", "password": f"vertippt{i}"})

    r = client.post("/api/v1/auth/login", json={"username": "normalo", "password": "RichtigesPasswort123456"})
    assert r.status_code == 200

    for i in range(3):
        r2 = client.post("/api/v1/auth/login", json={"username": "normalo", "password": f"wiedervertippt{i}"})
        assert r2.status_code == 401


def test_rate_limit_uses_robust_ip_fallback_chain():
    """Regressionstest: das Rate-Limiting nutzte vorher NUR X-Real-IP,
    nicht die robustere Fallback-Kette wie das Audit-Log -- dadurch
    haetten bei fehlender X-Real-IP-Konfiguration alle Nutzer dieselbe
    interne Docker-IP geteilt (ein Nutzer haette versehentlich alle
    anderen mit-limitieren koennen)."""
    from app.core.rate_limit import get_client_ip

    class FakeRequest:
        headers = {"cf-connecting-ip": "203.0.113.5"}
        client = None

    assert get_client_ip(FakeRequest()) == "203.0.113.5"


def test_password_change_invalidates_other_sessions_but_keeps_current(client):
    """Hardening: nach einer Passwort-Aenderung sollen alle ANDEREN
    aktiven Sessions sofort ungueltig werden (falls das Konto
    kompromittiert war), die eigene aktuelle Session aber bestehen
    bleiben."""
    import pyotp
    from fastapi.testclient import TestClient
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole
    from app.main import app as fastapi_app

    db = SessionLocal()
    db.add(User(username="multisession", password_hash=hash_password("AltesPasswort123456"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    client1 = TestClient(fastapi_app)
    r = client1.post("/api/v1/auth/login", json={"username": "multisession", "password": "AltesPasswort123456"})
    pending = r.json()["pending_token"]
    r = client1.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client1.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    client2 = TestClient(fastapi_app)
    r = client2.post("/api/v1/auth/login", json={"username": "multisession", "password": "AltesPasswort123456"})
    pending2 = r.json()["pending_token"]
    code2 = pyotp.TOTP(secret).now()
    client2.post("/api/v1/auth/2fa/totp/verify", json={"pending_token": pending2, "code": code2})

    assert client1.get("/api/v1/auth/me").status_code == 200
    assert client2.get("/api/v1/auth/me").status_code == 200

    r = client1.post("/api/v1/auth/me/password", json={"current_password": "AltesPasswort123456", "new_password": "NeuesPasswort1234567"})
    assert r.status_code == 200
    assert r.json()["other_sessions_revoked"] == 1

    assert client1.get("/api/v1/auth/me").status_code == 200
    assert client2.get("/api/v1/auth/me").status_code == 401

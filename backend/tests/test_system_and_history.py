"""Tests fuer System-Info, Docker-Status (Proxy gemockt) und Tool-Verlauf."""

from unittest.mock import patch

import pyotp

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def test_system_info_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.get("/api/v1/system/info")
    assert r.status_code == 403


def test_system_info_returns_plausible_values(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.get("/api/v1/system/info")
    assert r.status_code == 200
    data = r.json()
    assert data["cpu_count"] > 0
    assert 0 <= data["memory_percent"] <= 100
    assert data["memory_total_bytes"] > 0


def test_docker_status_via_mocked_proxy(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return [
                {"Names": ["/toolbox-backend"], "Image": "img", "State": "running", "Status": "Up 2h"},
                {"Names": ["/old"], "Image": "img2", "State": "exited", "Status": "Exited"},
            ]

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get("/api/v1/system/docker")

    assert r.status_code == 200
    assert r.json()["total"] == 2
    assert r.json()["running"] == 1


def test_docker_status_handles_proxy_unreachable(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    import httpx

    async def fake_get(self, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    with patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get("/api/v1/system/docker")

    assert r.status_code == 502


def test_tool_history_records_successful_runs(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    assert client.get("/api/v1/auth/me/history").json() == []

    r = client.post("/api/v1/tools/hash-generator", json={"text": "test", "algorithms": ["md5"]})
    assert r.status_code == 200

    history = client.get("/api/v1/auth/me/history").json()
    assert len(history) == 1
    assert history[0]["tool_slug"] == "hash-generator"
    assert history[0]["success"] is True


def test_tool_history_excludes_validation_errors(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/hash-generator", json={"text": "test", "algorithms": ["not-real"]})
    assert r.status_code == 422

    assert client.get("/api/v1/auth/me/history").json() == []


def test_tool_history_requires_auth(client):
    r = client.get("/api/v1/auth/me/history")
    assert r.status_code == 401

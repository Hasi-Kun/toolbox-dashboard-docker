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
                {"Names": ["/toolbox-backend"], "Id": "abc123", "Image": "img", "State": "running", "Status": "Up 2h"},
                {"Names": ["/toolbox-scanner"], "Id": "def456", "Image": "img2", "State": "exited", "Status": "Exited"},
            ]

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get("/api/v1/system/docker")

    assert r.status_code == 200
    assert r.json()["total"] == 2
    assert r.json()["running"] == 1


def test_docker_status_filters_out_unrelated_host_containers(client):
    """Der Host laeuft typischerweise weitere, voellig unabhaengige
    Container (andere selbst gehostete Dienste) -- die duerfen im
    Toolbox-Dashboard weder angezeigt noch dadurch ueberhaupt erst
    bekannt gemacht werden."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return [
                {"Names": ["/toolbox-backend"], "Id": "abc123", "Image": "img", "State": "running", "Status": "Up 2h"},
                {"Names": ["/nextcloud"], "Id": "xyz999", "Image": "nextcloud:latest", "State": "running", "Status": "Up 3d"},
                {"Names": ["/wireguard"], "Id": "wg111", "Image": "linuxserver/wireguard", "State": "running", "Status": "Up 3d"},
            ]

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get("/api/v1/system/docker")

    data = r.json()
    names = [c["name"] for c in data["containers"]]
    assert names == ["toolbox-backend"]
    assert "nextcloud" not in names
    assert "wireguard" not in names


def test_docker_status_handles_proxy_unreachable(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    import httpx

    async def fake_get(self, url, **kwargs):
        raise httpx.ConnectError("connection refused")

    with patch("httpx.AsyncClient.get", new=fake_get):
        r = client.get("/api/v1/system/docker")

    assert r.status_code == 502


# --- Container-Neustart -------------------------------------------------------

def test_restart_container_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member2", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member2", "AuchEinSicheresPW123")
    r = client.post("/api/v1/system/docker/toolbox-backend/restart")
    assert r.status_code == 403


def test_restart_container_succeeds_for_allowlisted_container(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    class FakeResponse:
        status_code = 204

    async def fake_post(self, url, **kwargs):
        assert "toolbox-backend" in url
        return FakeResponse()

    with patch("httpx.AsyncClient.post", new=fake_post):
        r = client.post("/api/v1/system/docker/toolbox-backend/restart")

    assert r.status_code == 200
    assert r.json() == {"success": True, "container": "toolbox-backend"}


def test_restart_container_rejects_non_allowlisted_name(client):
    """Kernsicherheitsgrenze: der Docker-Socket-Proxy selbst kennt keine
    Container-Namen-Einschraenkung (ALLOW_RESTARTS=1 dort erlaubt
    technisch JEDEN Container) -- diese Pruefung im Backend ist die
    tatsaechliche Grenze. Muss OHNE jeden Aufruf des Proxys ablehnen."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    async def fake_post(self, url, **kwargs):
        raise AssertionError("Der Proxy haette fuer einen fremden Container NIE aufgerufen werden duerfen")

    with patch("httpx.AsyncClient.post", new=fake_post):
        r = client.post("/api/v1/system/docker/nextcloud/restart")

    assert r.status_code == 403


def test_restart_container_logs_audit_event(client):
    from app.core.db import SessionLocal
    from app.models.user import AuditLogEntry

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    class FakeResponse:
        status_code = 204

    async def fake_post(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.post", new=fake_post):
        client.post("/api/v1/system/docker/toolbox-scanner/restart")

    db = SessionLocal()
    entry = db.query(AuditLogEntry).filter_by(event_type="docker_container_restart").first()
    db.close()
    assert entry is not None
    assert entry.username == "admin"
    assert entry.detail == "toolbox-scanner"
    assert entry.success is True


def test_restart_container_handles_proxy_failure(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    class FakeResponse:
        status_code = 500

    async def fake_post(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.post", new=fake_post):
        r = client.post("/api/v1/system/docker/toolbox-backend/restart")

    assert r.status_code == 502


# --- DNS-Cache-Flush (AdGuard Home) -------------------------------------------

def test_dns_cache_flush_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member3", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member3", "AuchEinSicheresPW123")
    r = client.post("/api/v1/system/dns-cache/flush")
    assert r.status_code == 403


def test_dns_cache_flush_fails_when_not_configured(client):
    from app.core.config import get_settings

    settings = get_settings()
    original = (settings.adguard_home_url, settings.adguard_home_username, settings.adguard_home_password)
    settings.adguard_home_url = None
    settings.adguard_home_username = None
    try:
        password = _create_admin()
        _login_with_totp_setup(client, "admin", password)
        r = client.post("/api/v1/system/dns-cache/flush")
        assert r.status_code == 400
    finally:
        settings.adguard_home_url, settings.adguard_home_username, settings.adguard_home_password = original


def test_dns_cache_flush_succeeds_when_configured(client):
    from app.core.config import get_settings

    settings = get_settings()
    original = (settings.adguard_home_url, settings.adguard_home_username, settings.adguard_home_password)
    settings.adguard_home_url = "http://adguard.local:3000"
    settings.adguard_home_username = "admin"
    settings.adguard_home_password = "secret"
    try:
        password = _create_admin()
        _login_with_totp_setup(client, "admin", password)

        class FakeResponse:
            status_code = 200

        async def fake_post(self, url, **kwargs):
            assert url == "http://adguard.local:3000/control/cache_clear"
            assert kwargs["auth"] == ("admin", "secret")
            return FakeResponse()

        with patch("httpx.AsyncClient.post", new=fake_post):
            r = client.post("/api/v1/system/dns-cache/flush")
        assert r.status_code == 200
        assert r.json() == {"success": True}
    finally:
        settings.adguard_home_url, settings.adguard_home_username, settings.adguard_home_password = original


def test_dns_cache_flush_logs_audit_event(client):
    from app.core.config import get_settings
    from app.core.db import SessionLocal
    from app.models.user import AuditLogEntry

    settings = get_settings()
    original = (settings.adguard_home_url, settings.adguard_home_username, settings.adguard_home_password)
    settings.adguard_home_url = "http://adguard.local:3000"
    settings.adguard_home_username = "admin"
    settings.adguard_home_password = "secret"
    try:
        password = _create_admin()
        _login_with_totp_setup(client, "admin", password)

        class FakeResponse:
            status_code = 200

        async def fake_post(self, url, **kwargs):
            return FakeResponse()

        with patch("httpx.AsyncClient.post", new=fake_post):
            client.post("/api/v1/system/dns-cache/flush")

        db = SessionLocal()
        entry = db.query(AuditLogEntry).filter_by(event_type="dns_cache_flush").first()
        db.close()
        assert entry is not None
        assert entry.success is True
        assert entry.username == "admin"
    finally:
        settings.adguard_home_url, settings.adguard_home_username, settings.adguard_home_password = original


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

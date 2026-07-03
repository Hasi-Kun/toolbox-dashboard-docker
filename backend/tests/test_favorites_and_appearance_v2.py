"""Tests fuer Favoriten und die erweiterten Appearance-Einstellungen
(Geschwindigkeit, Gradient-Farbe, Sternenhimmel, Maus-Interaktion)."""

import pyotp

from tests.conftest import create_admin as _create_admin


def _login_with_totp_setup(client, username: str, password: str) -> None:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def test_favorites_add_list_remove(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    assert client.get("/api/v1/auth/me/favorites").json() == []

    r = client.post("/api/v1/auth/me/favorites", json={"tool_slug": "ping"})
    assert r.status_code == 200

    favorites = client.get("/api/v1/auth/me/favorites").json()
    assert favorites == [{"tool_slug": "ping"}]

    r = client.delete("/api/v1/auth/me/favorites/ping")
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me/favorites").json() == []


def test_favorites_rejects_unknown_tool(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/auth/me/favorites", json={"tool_slug": "does-not-exist"})
    assert r.status_code == 422


def test_favorites_no_duplicate_on_double_add(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    client.post("/api/v1/auth/me/favorites", json={"tool_slug": "whois"})
    client.post("/api/v1/auth/me/favorites", json={"tool_slug": "whois"})
    assert len(client.get("/api/v1/auth/me/favorites").json()) == 1


def test_favorites_require_auth(client):
    r = client.get("/api/v1/auth/me/favorites")
    assert r.status_code == 401


def test_appearance_extended_fields_roundtrip(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch(
        "/api/v1/appearance",
        json={
            "background_style": "gradient",
            "animation_speed": 2.5,
            "gradient_color": "#FF00FF",
            "interactive_dots": False,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["animation_speed"] == 2.5
    assert data["gradient_color"] == "#FF00FF"
    assert data["interactive_dots"] is False


def test_appearance_speed_is_clamped(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/appearance", json={"background_style": "dots", "animation_speed": 99})
    assert r.json()["animation_speed"] == 3.0

    r = client.patch("/api/v1/appearance", json={"background_style": "dots", "animation_speed": 0.01})
    assert r.json()["animation_speed"] == 0.25


def test_appearance_rejects_invalid_hex_color(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/appearance", json={"background_style": "gradient", "gradient_color": "not-a-color"})
    assert r.status_code == 422


def test_appearance_accepts_starfield_style(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.patch("/api/v1/appearance", json={"background_style": "starfield"})
    assert r.status_code == 200
    assert r.json()["background_style"] == "starfield"

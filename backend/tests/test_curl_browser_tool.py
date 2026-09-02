"""Tests fuer das Curl Browser Tool. Gegen einen echten lokalen HTTP-
Echo-Server verifiziert (nicht gemockt) -- siehe conftest-Fixture
unten, die den Server fuer die Testdauer im Hintergrund startet.
"""

import json
import subprocess
import sys
import time

import pytest

from tests.conftest import create_admin as _create_admin


ECHO_SERVER_CODE = '''
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class EchoHandler(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        payload = {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Echo-Server", "true")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def log_message(self, *args): pass

HTTPServer(("127.0.0.1", 18899), EchoHandler).serve_forever()
'''


@pytest.fixture(scope="module")
def echo_server():
    proc = subprocess.Popen([sys.executable, "-c", ECHO_SERVER_CODE])
    time.sleep(0.5)
    yield "http://127.0.0.1:18899"
    proc.terminate()
    proc.wait(timeout=5)


def _login_with_totp_setup(client, username: str, password: str) -> None:
    import pyotp

    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    pending_token = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending_token})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending_token, "code": code})


def test_requires_admin(client):
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username="member1", password_hash=hash_password("AuchEinSicheresPW123"), role=UserRole.MEMBER.value, is_active=True))
    db.commit()
    db.close()

    _login_with_totp_setup(client, "member1", "AuchEinSicheresPW123")
    r = client.post("/api/v1/tools/curl-browser", json={"method": "GET", "url": "https://example.com"})
    assert r.status_code == 403


def test_get_request_with_custom_header(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post(
        "/api/v1/tools/curl-browser",
        json={"method": "GET", "url": f"{echo_server}/test", "headers": [{"key": "X-Test", "value": "hallo-welt"}]},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status_code"] == 200
    body = json.loads(data["response_body"])
    assert body["headers"]["X-Test"] == "hallo-welt"
    assert "curl -i -sS -X GET" in data["curl_command"]
    assert "X-Test: hallo-welt" in data["curl_command"]


def test_post_request_with_body(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post(
        "/api/v1/tools/curl-browser",
        json={"method": "POST", "url": f"{echo_server}/api", "body": '{"key": "value"}', "headers": [{"key": "Content-Type", "value": "application/json"}]},
    )
    assert r.status_code == 200
    data = r.json()
    body = json.loads(data["response_body"])
    assert body["method"] == "POST"
    assert body["body"] == '{"key": "value"}'


def test_rejects_invalid_url(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/curl-browser", json={"method": "GET", "url": "nicht gueltig!!!"})
    assert r.status_code == 422


def test_unreachable_target_returns_error_not_exception(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/curl-browser", json={"method": "GET", "url": "http://192.0.2.1/"})
    assert r.status_code == 200
    data = r.json()
    assert data["status_code"] is None
    assert data["error"] is not None


def test_curl_command_shown_even_on_error(client):
    """Der curl-Befehl soll auch bei Fehlschlag angezeigt werden --
    hilfreich, um den Befehl trotzdem manuell auszuprobieren."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/curl-browser", json={"method": "GET", "url": "http://192.0.2.1/"})
    data = r.json()
    assert "curl" in data["curl_command"]
    assert "192.0.2.1" in data["curl_command"]


def test_rejects_too_many_headers(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    headers = [{"key": f"X-Test-{i}", "value": "x"} for i in range(31)]
    r = client.post("/api/v1/tools/curl-browser", json={"method": "GET", "url": "https://example.com", "headers": headers})
    assert r.status_code == 422

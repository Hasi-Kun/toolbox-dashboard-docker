"""Tests fuer den Log4j-Vuln-Tester. Gegen einen echten lokalen HTTP-
Echo-Server verifiziert (nicht gemockt)."""

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
        payload = {"headers": dict(self.headers)}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self): self._handle()
    def log_message(self, *args): pass

HTTPServer(("127.0.0.1", 18898), EchoHandler).serve_forever()
'''


@pytest.fixture(scope="module")
def echo_server():
    proc = subprocess.Popen([sys.executable, "-c", ECHO_SERVER_CODE])
    time.sleep(0.5)
    yield "http://127.0.0.1:18898"
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
    r = client.post("/api/v1/tools/log4j-vuln-tester", json={"url": "https://example.com", "callback_domain": "abc.interact.sh"})
    assert r.status_code == 403


def test_sends_jndi_payloads_to_all_tested_headers(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/log4j-vuln-tester", json={"url": f"{echo_server}/test", "callback_domain": "abc123.interact.sh"})
    assert r.status_code == 200
    data = r.json()
    assert data["requests_sent"] == 7
    assert all("abc123.interact.sh" in h["payload"] for h in data["tested_headers"])
    assert all("${jndi:ldap://" in h["payload"] for h in data["tested_headers"])


def test_all_payloads_contain_unique_sub_markers(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/log4j-vuln-tester", json={"url": f"{echo_server}/test", "callback_domain": "abc123.interact.sh"})
    data = r.json()
    markers = [h["payload"].split("ldap://")[1].split(".")[0] for h in data["tested_headers"]]
    assert len(set(markers)) == len(markers)


def test_rejects_invalid_callback_domain(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/log4j-vuln-tester", json={"url": "https://example.com", "callback_domain": "not a valid domain!!!"})
    assert r.status_code == 422


def test_strips_scheme_and_path_from_callback_domain(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post(
        "/api/v1/tools/log4j-vuln-tester",
        json={"url": f"{echo_server}/test", "callback_domain": "https://abc123.interact.sh/some/path"},
    )
    assert r.status_code == 200
    assert r.json()["callback_domain"] == "abc123.interact.sh"


def test_rejects_invalid_target_url(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/log4j-vuln-tester", json={"url": "not a url!!!", "callback_domain": "abc.interact.sh"})
    assert r.status_code == 422


def test_response_includes_note_about_manual_callback_check(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/tools/log4j-vuln-tester", json={"url": f"{echo_server}/test", "callback_domain": "abc.interact.sh"})
    data = r.json()
    assert "session_marker" in data
    assert len(data["note"]) > 0

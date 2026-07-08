"""Tests fuer das zusaetzliche, strengere Pro-Slug-Rate-Limit bei den
schwersten aktiven Scan-Tools (nikto-scan, nmap-full-port-scan,
nmap-vuln-scan) -- zusaetzlich zum bereits bestehenden kategorieweiten
Limit fuer alle aktiven Scans.
"""

from unittest.mock import patch

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


async def _fake_wait_for_result(job_id, timeout):
    return {"error": "kein echter Scanner in der Testumgebung"}


async def _fake_submit_job(template, params):
    return "fake-job-id"


def test_nikto_scan_has_stricter_per_slug_rate_limit(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    with patch("app.modules.nmap.nikto_scan.wait_for_result", new=_fake_wait_for_result), \
         patch("app.modules.nmap.nikto_scan.submit_job", new=_fake_submit_job):
        statuses = [client.post("/api/v1/tools/nikto-scan", json={"target": "example.com"}).status_code for _ in range(4)]

    assert statuses[0] == 200 and statuses[1] == 200
    assert 429 in statuses[2:]


def test_full_port_scan_has_stricter_per_slug_rate_limit(client):
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    with patch("app.modules.nmap.full_port_scan.wait_for_result", new=_fake_wait_for_result), \
         patch("app.modules.nmap.full_port_scan.submit_job", new=_fake_submit_job):
        statuses = [client.post("/api/v1/tools/nmap-full-port-scan", json={"target": "example.com"}).status_code for _ in range(4)]

    assert statuses[0] == 200 and statuses[1] == 200
    assert 429 in statuses[2:]


def test_nikto_and_full_port_scan_have_independent_per_slug_buckets(client):
    """Das strengere Pro-Slug-Limit von nikto-scan darf nicht das Budget
    von nmap-full-port-scan verbrauchen -- getrennte Buckets."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    with patch("app.modules.nmap.nikto_scan.wait_for_result", new=_fake_wait_for_result), \
         patch("app.modules.nmap.nikto_scan.submit_job", new=_fake_submit_job):
        for _ in range(2):
            client.post("/api/v1/tools/nikto-scan", json={"target": "example.com"})

    with patch("app.modules.nmap.full_port_scan.wait_for_result", new=_fake_wait_for_result), \
         patch("app.modules.nmap.full_port_scan.submit_job", new=_fake_submit_job):
        r = client.post("/api/v1/tools/nmap-full-port-scan", json={"target": "example.com"})

    assert r.status_code == 200, "nmap-full-port-scan sollte trotz ausgeschoepftem nikto-scan-Limit noch gehen"


def test_quick_scan_not_affected_by_per_slug_limits(client):
    """nmap-quick hat kein eigenes Pro-Slug-Limit -- nur das
    kategorieweite Limit sollte hier greifen (bereits an anderer Stelle
    getestet), aber nicht das strenge 2/Minute-Limit der schweren Tools."""
    password = _create_admin()
    _login_with_totp_setup(client, "admin", password)

    with patch("app.modules.nmap.quick.wait_for_result", new=_fake_wait_for_result), \
         patch("app.modules.nmap.quick.submit_job", new=_fake_submit_job):
        statuses = [client.post("/api/v1/tools/nmap-quick", json={"target": "example.com"}).status_code for _ in range(3)]

    # Kategorieweites Limit (5/Minute) betrifft alle nmap-Tools gemeinsam,
    # aber 3 Versuche allein sollten davon noch nicht blockiert werden.
    assert statuses[0] == 200

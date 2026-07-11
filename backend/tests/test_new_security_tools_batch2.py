"""Tests fuer die zweite Batch neuer Security-/OSINT-Tools: Shodan
InternetDB, WAF-Detector, Open-Redirect-Checker, Cookie-Security-
Analyse, HTTP-Methoden-Check, DMARC-Staerke-Bewertung, SRI-Checker.
"""

from unittest.mock import patch

import pytest
from pydantic import ValidationError


# --- Shodan InternetDB ------------------------------------------------------

def test_shodan_internetdb_rejects_hostname_not_ip():
    from app.modules.osint.shodan_internetdb import ShodanInternetDbModule

    with pytest.raises(ValidationError):
        ShodanInternetDbModule.Input(ip="example.com")


@pytest.mark.asyncio
async def test_shodan_internetdb_parses_known_response_shape():
    from app.modules.osint.shodan_internetdb import ShodanInternetDbModule

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "ip": "51.83.59.99", "ports": [22, 80, 443, 500],
                "cpes": ["cpe:/a:f5:nginx", "cpe:/a:openbsd:openssh:7.4"],
                "hostnames": ["www.sampleresponse.fr"], "tags": ["vpn"],
                "vulns": ["CVE-2017-15906"],
            }

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await ShodanInternetDbModule().run(ShodanInternetDbModule.Input(ip="51.83.59.99"))

    assert result.found is True
    assert result.ports == [22, 80, 443, 500]
    assert "CVE-2017-15906" in result.vulns


@pytest.mark.asyncio
async def test_shodan_internetdb_404_is_not_found_not_error():
    from app.modules.osint.shodan_internetdb import ShodanInternetDbModule

    class FakeResponse:
        status_code = 404

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await ShodanInternetDbModule().run(ShodanInternetDbModule.Input(ip="203.0.113.99"))

    assert result.success is True
    assert result.found is False


# --- WAF Detector ------------------------------------------------------------

@pytest.mark.asyncio
async def test_waf_detector_detects_cloudflare_via_header():
    from app.modules.security.waf_detector import WafDetectorModule

    class FakeResponse:
        status_code = 200
        headers = {"server": "cloudflare", "cf-ray": "abc123"}
        cookies = {}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await WafDetectorModule().run(WafDetectorModule.Input(domain="example.com"))

    assert "Cloudflare" in result.detected


@pytest.mark.asyncio
async def test_waf_detector_detects_via_cookie():
    from app.modules.security.waf_detector import WafDetectorModule

    class FakeResponse:
        status_code = 200
        headers = {}
        cookies = {"incap_ses_123_abc": "value", "visid_incap_999": "value"}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await WafDetectorModule().run(WafDetectorModule.Input(domain="example.com"))

    assert "Imperva Incapsula" in result.detected


@pytest.mark.asyncio
async def test_waf_detector_no_false_positive_on_plain_server():
    from app.modules.security.waf_detector import WafDetectorModule

    class FakeResponse:
        status_code = 200
        headers = {"server": "gunicorn"}
        cookies = {}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await WafDetectorModule().run(WafDetectorModule.Input(domain="example.com"))

    assert result.detected == []


# --- Open Redirect Checker --------------------------------------------------

def test_open_redirect_checker_rejects_invalid_url():
    from app.modules.security.open_redirect_checker import OpenRedirectCheckerModule

    with pytest.raises(ValidationError):
        OpenRedirectCheckerModule.Input(url="not a url; rm -rf /")


@pytest.mark.asyncio
async def test_open_redirect_checker_no_false_positive_without_real_redirect():
    """Regressionstest fuer den gefundenen Bug: der Test-String steckt
    selbst als Query-Parameter in der angefragten URL -- ein reiner
    Substring-Check haette IMMER faelschlich 'verwundbar' gemeldet."""
    from app.modules.security.open_redirect_checker import OpenRedirectCheckerModule

    class FakeResponse:
        def __init__(self, url):
            self.url = url
            self.history = []  # kein echter Redirect

    async def fake_get(self, url, **kwargs):
        return FakeResponse(url)  # httpx gibt bei keinem Redirect die urspruengliche URL zurueck

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await OpenRedirectCheckerModule().run(OpenRedirectCheckerModule.Input(url="https://safe-example.com"))

    assert len(result.vulnerable_parameters) == 0


@pytest.mark.asyncio
async def test_open_redirect_checker_detects_real_redirect():
    from app.modules.security.open_redirect_checker import OpenRedirectCheckerModule

    class FakeResponse:
        def __init__(self, url, history):
            self.url = url
            self.history = history

    async def fake_get(self, url, **kwargs):
        if "redirect=" in url:
            return FakeResponse("https://example.com/toolbox-redirect-probe", history=["dummy"])
        return FakeResponse(url, history=[])

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await OpenRedirectCheckerModule().run(OpenRedirectCheckerModule.Input(url="https://vulnerable.example.com/login"))

    vulnerable_names = [v.parameter for v in result.vulnerable_parameters]
    assert vulnerable_names == ["redirect"]


# --- Cookie Security Analyzer ------------------------------------------------

@pytest.mark.asyncio
async def test_cookie_analyzer_flags_missing_flags():
    from app.modules.security.cookie_security_analyzer import CookieSecurityAnalyzerModule

    class FakeHeaders:
        def get_list(self, key):
            if key == "set-cookie":
                return ["session=abc123; Path=/"]
            return []

    class FakeResponse:
        headers = FakeHeaders()

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await CookieSecurityAnalyzerModule().run(CookieSecurityAnalyzerModule.Input(domain="example.com"))

    assert len(result.cookies) == 1
    cookie = result.cookies[0]
    assert cookie.secure is False
    assert cookie.http_only is False
    assert len(cookie.issues) >= 2


@pytest.mark.asyncio
async def test_cookie_analyzer_no_issues_for_well_configured_cookie():
    from app.modules.security.cookie_security_analyzer import CookieSecurityAnalyzerModule

    class FakeHeaders:
        def get_list(self, key):
            if key == "set-cookie":
                return ["session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"]
            return []

    class FakeResponse:
        headers = FakeHeaders()

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await CookieSecurityAnalyzerModule().run(CookieSecurityAnalyzerModule.Input(domain="example.com"))

    assert result.cookies[0].issues == []


# --- HTTP Methods Checker ----------------------------------------------------

@pytest.mark.asyncio
async def test_http_methods_checker_flags_risky_methods():
    from app.modules.security.http_methods_checker import HttpMethodsCheckerModule

    class FakeResponse:
        headers = {"allow": "GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS"}

    async def fake_request(self, method, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.request", new=fake_request):
        result = await HttpMethodsCheckerModule().run(HttpMethodsCheckerModule.Input(url="https://example.com"))

    assert "TRACE" in result.risky_methods_found
    assert "PUT" in result.risky_methods_found
    assert "DELETE" in result.risky_methods_found
    assert "GET" not in result.risky_methods_found


@pytest.mark.asyncio
async def test_http_methods_checker_no_risky_methods():
    from app.modules.security.http_methods_checker import HttpMethodsCheckerModule

    class FakeResponse:
        headers = {"allow": "GET, HEAD, POST, OPTIONS"}

    async def fake_request(self, method, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.request", new=fake_request):
        result = await HttpMethodsCheckerModule().run(HttpMethodsCheckerModule.Input(url="https://example.com"))

    assert result.risky_methods_found == []


# --- DMARC Strength ----------------------------------------------------------

def test_dmarc_strength_reject_is_strong():
    from app.modules.mail.dmarc import DmarcCheckModule

    score, label = DmarcCheckModule._compute_strength("reject", 100, True)
    assert label == "stark"
    assert score == 100


def test_dmarc_strength_none_is_weak():
    from app.modules.mail.dmarc import DmarcCheckModule

    score, label = DmarcCheckModule._compute_strength("none", 100, False)
    assert label == "schwach"


def test_dmarc_strength_no_policy_is_none():
    from app.modules.mail.dmarc import DmarcCheckModule

    score, label = DmarcCheckModule._compute_strength(None, 100, False)
    assert label == "kein DMARC"
    assert score == 0


def test_dmarc_strength_partial_percentage_reduces_score():
    from app.modules.mail.dmarc import DmarcCheckModule

    full_score, _ = DmarcCheckModule._compute_strength("reject", 100, False)
    partial_score, _ = DmarcCheckModule._compute_strength("reject", 50, False)
    assert partial_score < full_score


# --- SRI Checker --------------------------------------------------------------

def test_sri_checker_rejects_invalid_url():
    from app.modules.security.sri_checker import SriCheckerModule

    with pytest.raises(ValidationError):
        SriCheckerModule.Input(url="not a url; rm -rf /")


@pytest.mark.asyncio
async def test_sri_checker_detects_missing_integrity():
    from app.modules.security.sri_checker import SriCheckerModule

    class FakeResponse:
        url = "https://example.com/"
        text = (
            '<html><head>'
            '<script src="https://cdn.example.net/lib.js"></script>'
            '<script src="https://cdn.example.net/safe.js" integrity="sha384-abc123"></script>'
            '<link rel="stylesheet" href="https://cdn.example.net/style.css">'
            '</head></html>'
        )

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await SriCheckerModule().run(SriCheckerModule.Input(url="https://example.com"))

    assert result.missing_integrity_count == 2  # lib.js + style.css ohne integrity
    scripts_with_integrity = [r for r in result.external_resources if r.has_integrity]
    assert len(scripts_with_integrity) == 1


@pytest.mark.asyncio
async def test_sri_checker_ignores_same_origin_resources():
    from app.modules.security.sri_checker import SriCheckerModule

    class FakeResponse:
        url = "https://example.com/"
        text = '<html><head><script src="/static/app.js"></script></head></html>'

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await SriCheckerModule().run(SriCheckerModule.Input(url="https://example.com"))

    assert result.external_resources == []


def test_all_new_batch2_modules_registered():
    from app.modules import get_registry

    registry = get_registry()
    for slug in [
        "shodan-internetdb", "waf-detector", "open-redirect-checker",
        "cookie-security-analyzer", "http-methods-checker", "sri-checker",
    ]:
        assert slug in registry, f"{slug} nicht registriert"

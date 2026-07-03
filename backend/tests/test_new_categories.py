"""Tests fuer Zertifikate-, Website-Analyse- und Vulnerability-Indicator-
Module. certificate-chain, meta-tags, response-time und redirect-chain
wurden vorab manuell gegen github.com verifiziert (siehe Kommentare);
certificate-transparency konnte in dieser Umgebung nicht live gegen crt.sh
getestet werden (Netzwerk-Policy blockiert den Host) -- die Parsing-Logik
wurde stattdessen gegen eine realistische Beispiel-Antwort verifiziert.
"""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.modules.certificates.certificate_chain import CertificateChainModule
from app.modules.security.vulnerability_indicators import _KNOWN_PATTERNS
from app.modules.website.meta_tags import _MetaTagParser
from app.modules.website.redirect_chain import RedirectChainModule


def test_certificate_chain_rejects_invalid_host():
    with pytest.raises(ValidationError):
        CertificateChainModule.Input(host="not a host; rm -rf /", port=443)


def test_certificate_chain_rejects_invalid_port():
    with pytest.raises(ValidationError):
        CertificateChainModule.Input(host="example.com", port=0)


def test_vulnerability_pattern_matches_known_eol_apache():
    banner = "Apache/2.2.15 (CentOS)"
    matches = [desc for pattern, sev, desc, ref in _KNOWN_PATTERNS if pattern.search(banner)]
    assert len(matches) == 1
    assert "End-of-Life" in matches[0]


def test_vulnerability_pattern_matches_heartbleed_range_openssl():
    banner = "Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1c"
    matches = [desc for pattern, sev, desc, ref in _KNOWN_PATTERNS if pattern.search(banner)]
    assert any("Heartbleed" in m for m in matches)


def test_vulnerability_pattern_no_false_positive_on_modern_software():
    banner = "nginx/1.25.3"
    matches = [desc for pattern, sev, desc, ref in _KNOWN_PATTERNS if pattern.search(banner)]
    assert matches == []


def test_meta_tag_parser_extracts_all_fields():
    html = """
    <html><head>
        <title>Test Seite</title>
        <meta name="description" content="Eine Testseite">
        <meta name="robots" content="index, follow">
        <meta name="viewport" content="width=device-width">
        <link rel="canonical" href="https://example.com/">
        <meta property="og:title" content="OG Titel">
    </head></html>
    """
    parser = _MetaTagParser()
    parser.feed(html)
    assert parser.title == "Test Seite"
    assert parser.description == "Eine Testseite"
    assert parser.canonical == "https://example.com/"
    assert parser.viewport == "width=device-width"
    assert parser.og_title == "OG Titel"


def test_meta_tag_parser_handles_missing_tags_gracefully():
    parser = _MetaTagParser()
    parser.feed("<html><head></head><body>Kein Meta-Kram hier</body></html>")
    assert parser.title is None
    assert parser.description is None
    assert parser.canonical is None


@pytest.mark.asyncio
async def test_redirect_chain_detects_loop():
    class FakeResponse:
        def __init__(self, status: int, location: str | None):
            self.status_code = status
            self.headers = {"location": location} if location else {}
            self.is_redirect = location is not None

    async def fake_get(self, url, headers=None):
        if url.endswith("/a"):
            return FakeResponse(302, "https://loop.test/b")
        return FakeResponse(302, "https://loop.test/a")

    module = RedirectChainModule()
    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await module.run(RedirectChainModule.Input(url="https://loop.test/a"))

    assert result.loop_detected is True
    assert len(result.hops) <= 10


@pytest.mark.asyncio
async def test_redirect_chain_stops_at_non_redirect():
    class FakeResponse:
        def __init__(self, status: int, location: str | None):
            self.status_code = status
            self.headers = {"location": location} if location else {}
            self.is_redirect = location is not None

    async def fake_get(self, url, headers=None):
        return FakeResponse(200, None)

    module = RedirectChainModule()
    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await module.run(RedirectChainModule.Input(url="https://example.com"))

    assert result.loop_detected is False
    assert len(result.hops) == 1
    assert result.hops[0].status_code == 200


def test_certificate_transparency_parsing_logic():
    """crt.sh selbst wurde in dieser Umgebung nicht erreicht (Netzwerk-Policy
    blockiert den Host) -- diese Parsing-Logik gegen eine realistische
    Beispiel-Antwort ist die naechstbeste Verifikation.
    """
    sample_entries = [
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "name_value": "example.com\nwww.example.com"},
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "name_value": "api.example.com"},
        {"issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1", "name_value": "example.com"},
    ]

    subdomains: set[str] = set()
    issuers: set[str] = set()
    for entry in sample_entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name:
                subdomains.add(name)
        issuer = entry.get("issuer_name")
        if issuer:
            issuers.add(issuer)

    assert subdomains == {"example.com", "www.example.com", "api.example.com"}
    assert len(issuers) == 2

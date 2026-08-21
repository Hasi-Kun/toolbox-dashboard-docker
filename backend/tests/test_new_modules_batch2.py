"""Tests fuer die neuen Module dieser Runde. Alle wurden vorab manuell gegen
echte Ziele verifiziert (siehe Kommentare in den jeweiligen Modulen) --
crt.sh, ip-api.com und OCSP-Responder waren in der Entwicklungsumgebung
durch Netzwerk-Policy/Sandbox-Proxy nicht direkt erreichbar, dort wurde
stattdessen die Parsing-Logik gegen realistische Beispieldaten getestet.
"""

import hashlib

import pytest
from pydantic import ValidationError

from app.modules.converter.hash_identifier import HashIdentifierModule
from app.modules.mail.dane_check import DaneCheckModule
from app.modules.mail.smtp_tls_check import SmtpTlsCheckModule
from app.modules.website.sitemap_check import _SITEMAP_NS
from app.core.security import hash_password


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_md5_and_sha256():
    md5 = hashlib.md5(b"test").hexdigest()
    sha256 = hashlib.sha256(b"test").hexdigest()

    r1 = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=md5))
    assert any("MD5" in a for a in r1.possible_algorithms)

    r2 = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=sha256))
    assert any("SHA-256" in a for a in r2.possible_algorithms)


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_our_own_argon2_format():
    # Das ist das exakte Format, das die App selbst fuer Benutzerpasswoerter nutzt
    argon2_hash = hash_password("test-password-123456")
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=argon2_hash))
    assert "Argon2" in result.possible_algorithms


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_bcrypt():
    real_bcrypt = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=real_bcrypt))
    assert "bcrypt" in result.possible_algorithms


@pytest.mark.asyncio
async def test_hash_identifier_returns_note_for_unknown_format():
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value="not-a-real-hash-at-all"))
    assert result.possible_algorithms == []
    assert result.note is not None


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_wordpress_and_phpbb3():
    wp = "$P$BiTOhOj3ukMgCci2juN0HRbCdDRqeh."
    r1 = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=wp))
    assert any("WordPress" in a for a in r1.possible_algorithms)

    phpbb3 = "$H$9kyOtE8CDqMJ44yfn9PFz2E.L2oVzL1"
    r2 = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=phpbb3))
    assert any("phpBB3" in a for a in r2.possible_algorithms)


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_sha512crypt_and_apr1():
    sha512crypt = "$6$rounds=5000$abcdefgh$1J8rI.mJReeMvpKUZbSlY1J8rI.mJReeMvpKUZbSlY1J8rI.mJReeMvpKUZbSlY1"
    r1 = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=sha512crypt))
    assert any("SHA-512 crypt" in a for a in r1.possible_algorithms)

    apr1 = "$apr1$qAUKoKlG$3LuCncByN76eLxZAh/Ldr1"
    r2 = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=apr1))
    assert any("APR1" in a for a in r2.possible_algorithms)


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_django_pbkdf2():
    value = "pbkdf2_sha256$260000$saltsalt$aGFzaHZhbHVlYmFzZTY0ZW5jb2RlZA=="
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=value))
    assert any("PBKDF2-SHA256" in a for a in result.possible_algorithms)


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_sam_lm_nt_pair():
    value = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=value))
    assert any("SAM" in a for a in result.possible_algorithms)


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_mysql41_password():
    value = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=value))
    assert any("MySQL" in a for a in result.possible_algorithms)


@pytest.mark.asyncio
async def test_hash_identifier_flags_jwt_as_not_a_hash():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=jwt))
    assert any("JWT" in a for a in result.possible_algorithms)
    assert result.note is not None and "JWT Security Analyzer" in result.note


@pytest.mark.asyncio
async def test_hash_identifier_recognizes_hash_salt_colon_format():
    value = "5d41402abc4b2a76b9719d911017c592:somesalt"
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=value))
    assert any("MD5" in a for a in result.possible_algorithms)
    assert result.note is not None and "hash:salt" in result.note


@pytest.mark.asyncio
async def test_hash_identifier_ambiguous_length_note_present():
    # 32 Hex-Zeichen sind laengenidentisch fuer MD5/NTLM/MD4/... -- die Antwort
    # muss auf die Mehrdeutigkeit hinweisen statt sich auf einen Algorithmus festzulegen.
    md5 = hashlib.md5(b"ambiguous").hexdigest()
    result = await HashIdentifierModule().run(HashIdentifierModule.Input(hash_value=md5))
    assert len(result.possible_algorithms) > 1
    assert result.note is not None and "Mehrere Algorithmen" in result.note


def test_dane_check_rejects_invalid_domain():
    with pytest.raises(ValidationError):
        DaneCheckModule.Input(domain="not a domain; rm -rf /", port=25)


def test_smtp_tls_check_only_allows_standard_ports():
    with pytest.raises(ValidationError):
        SmtpTlsCheckModule.Input(host="example.com", port=2525)
    # Standardports sind erlaubt
    SmtpTlsCheckModule.Input(host="example.com", port=25)
    SmtpTlsCheckModule.Input(host="example.com", port=587)
    SmtpTlsCheckModule.Input(host="example.com", port=465)


def test_sitemap_parsing_standard_format():
    import xml.etree.ElementTree as ET

    sample = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://example.com/</loc></url>"
        "<url><loc>https://example.com/about</loc></url>"
        "</urlset>"
    )
    root = ET.fromstring(sample)
    is_index = root.tag == f"{_SITEMAP_NS}sitemapindex"
    entries = root.findall(f"{_SITEMAP_NS}url")
    urls = [loc.text.strip() for entry in entries if (loc := entry.find(f"{_SITEMAP_NS}loc")) is not None and loc.text]

    assert is_index is False
    assert urls == ["https://example.com/", "https://example.com/about"]


def test_sitemap_parsing_index_format():
    import xml.etree.ElementTree as ET

    sample = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<sitemap><loc>https://example.com/sitemap-a.xml</loc></sitemap>"
        "<sitemap><loc>https://example.com/sitemap-b.xml</loc></sitemap>"
        "</sitemapindex>"
    )
    root = ET.fromstring(sample)
    is_index = root.tag == f"{_SITEMAP_NS}sitemapindex"
    entries = root.findall(f"{_SITEMAP_NS}sitemap")
    urls = [loc.text.strip() for entry in entries if (loc := entry.find(f"{_SITEMAP_NS}loc")) is not None and loc.text]

    assert is_index is True
    assert len(urls) == 2


@pytest.mark.asyncio
async def test_ip_geolocation_parses_realistic_response():
    from unittest.mock import patch

    from app.modules.network.ip_geolocation import IpGeolocationModule

    sample_response = {
        "status": "success", "country": "United States", "regionName": "California",
        "city": "Mountain View", "zip": "94043", "lat": 37.4056, "lon": -122.0775,
        "timezone": "America/Los_Angeles", "isp": "Google LLC", "org": "Google Public DNS", "query": "8.8.8.8",
    }

    class FakeResponse:
        def json(self):
            return sample_response

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await IpGeolocationModule().run(IpGeolocationModule.Input(target="8.8.8.8"))

    assert result.success is True
    assert result.city == "Mountain View"
    assert result.map_embed_url is not None
    assert "openstreetmap.org/export/embed.html" in result.map_embed_url


def test_ghost_sender_check_rejects_invalid_domain():
    from app.modules.mail.ghost_sender_check import GhostSenderCheckModule

    with pytest.raises(ValidationError):
        GhostSenderCheckModule.Input(domain="not a domain; rm -rf /")


def test_blacklist_check_rejects_invalid_target():
    from app.modules.mail.blacklist_check import BlacklistCheckModule

    with pytest.raises(ValidationError):
        BlacklistCheckModule.Input(target="not a domain; rm -rf /")


def test_ocsp_check_rejects_invalid_host():
    from app.modules.certificates.ocsp_check import OcspCheckModule

    with pytest.raises(ValidationError):
        OcspCheckModule.Input(host="not a host; rm -rf /", port=443)


def test_broken_links_rejects_invalid_domain():
    from app.modules.website.broken_links import BrokenLinksModule

    with pytest.raises(ValidationError):
        BrokenLinksModule.Input(domain="not a domain; rm -rf /")


def test_all_new_modules_registered_with_correct_categories():
    from app.modules import get_registry

    registry = get_registry()
    expected = {
        "dane-check": "mail",
        "smtp-tls-check": "mail",
        "blacklist-check": "mail",
        "ghost-sender-check": "mail",
        "ocsp-check": "certificates",
        "broken-links-checker": "website",
        "sitemap-check": "website",
        "ip-geolocation": "network",
        "hash-identifier": "converter",
    }
    for slug, category in expected.items():
        assert slug in registry, f"{slug} nicht registriert"
        assert registry[slug].category == category

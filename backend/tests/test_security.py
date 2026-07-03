"""Tests fuer die Security-Module. SSL Checker/Headers/robots.txt/security.txt
wurden vorab manuell gegen echte Server verifiziert (siehe Kommentare in den
Modulen); hier wird die reine Parsing-/Validierungslogik pruefbar abgedeckt.
"""

import pytest
from pydantic import ValidationError

from app.modules.security.headers import SecurityHeadersModule
from app.modules.security.robots import RobotsTxtModule
from app.modules.security.security_txt import SecurityTxtModule
from app.modules.security.ssl_checker import SslCheckerModule


def test_ssl_checker_rejects_invalid_host():
    with pytest.raises(ValidationError):
        SslCheckerModule.Input(host="not a host; rm -rf /", port=443)


def test_ssl_checker_rejects_invalid_port():
    with pytest.raises(ValidationError):
        SslCheckerModule.Input(host="example.com", port=99999)


def test_headers_domain_validator_strips_scheme_and_path():
    data = SecurityHeadersModule.Input(domain="https://example.com/some/path")
    assert data.domain == "example.com"


def test_robots_txt_parses_multiple_user_agents_and_sitemaps():
    sample = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /private\n"
        "Allow: /public\n"
        "\n"
        "User-agent: Googlebot\n"
        "Disallow: /no-google\n"
        "\n"
        "Sitemap: https://example.com/sitemap.xml\n"
    )
    rules, sitemaps = RobotsTxtModule._parse(sample)

    assert len(rules) == 2
    assert rules[0].user_agent == "*"
    assert rules[0].disallow == ["/admin", "/private"]
    assert rules[0].allow == ["/public"]
    assert rules[1].user_agent == "Googlebot"
    assert rules[1].disallow == ["/no-google"]
    assert sitemaps == ["https://example.com/sitemap.xml"]


def test_robots_txt_ignores_comments():
    sample = "# comment\nUser-agent: *\n# another comment\nDisallow: /x\n"
    rules, _ = RobotsTxtModule._parse(sample)
    assert rules[0].disallow == ["/x"]


def test_security_txt_parses_required_fields():
    sample = (
        "Contact: https://example.com/security\n"
        "Contact: mailto:security@example.com\n"
        "Expires: 2027-01-01T00:00:00.000Z\n"
        "Policy: https://example.com/disclosure-policy\n"
        "Preferred-Languages: en, de\n"
    )
    result = SecurityTxtModule._parse("example.com", sample)

    assert result.found is True
    assert result.contact == ["https://example.com/security", "mailto:security@example.com"]
    assert result.expires == "2027-01-01T00:00:00.000Z"
    assert result.policy == "https://example.com/disclosure-policy"
    assert result.preferred_languages == "en, de"
    assert result.warnings == []


def test_security_txt_warns_on_missing_required_fields():
    sample = "Policy: https://example.com/disclosure-policy\n"
    result = SecurityTxtModule._parse("example.com", sample)

    assert any("Contact" in w for w in result.warnings)
    assert any("Expires" in w for w in result.warnings)

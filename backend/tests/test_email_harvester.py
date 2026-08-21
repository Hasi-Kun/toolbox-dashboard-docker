"""Tests fuer den E-Mail-Adressen-Finder (DMARC/WHOIS/Website-Quellen)."""

from unittest.mock import patch

import pytest
from pydantic import ValidationError


def test_email_harvester_registered():
    from app.modules import get_registry

    assert "email-harvester" in get_registry()


def test_email_harvester_rejects_invalid_domain():
    from app.modules.osint.email_harvester import EmailHarvesterModule

    with pytest.raises(ValidationError):
        EmailHarvesterModule.Input(domain="not a domain; rm -rf /")


@pytest.mark.asyncio
async def test_finds_dmarc_email():
    from app.modules.osint.email_harvester import EmailHarvesterModule

    async def fake_query(name, rtype, timeout=5):
        if "_dmarc" in name:
            return {"success": True, "records": ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com'], "error": None}
        return {"success": False, "records": [], "error": "not found"}

    async def fake_whois(args, timeout):
        return {"success": True, "stdout": "", "stderr": "", "returncode": 0, "error": None}

    class FakeResponse:
        text = "<html>no mailto here</html>"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("app.modules.osint.email_harvester.query", new=fake_query), \
         patch("app.modules.osint.email_harvester.run_subprocess", new=fake_whois), \
         patch("httpx.AsyncClient.get", new=fake_get):
        result = await EmailHarvesterModule().run(EmailHarvesterModule.Input(domain="example.com"))

    addresses = [f.address for f in result.found]
    assert "dmarc@example.com" in addresses
    dmarc_entry = next(f for f in result.found if f.address == "dmarc@example.com")
    assert dmarc_entry.source == "dmarc"


@pytest.mark.asyncio
async def test_finds_whois_and_website_emails():
    from app.modules.osint.email_harvester import EmailHarvesterModule

    async def fake_query(name, rtype, timeout=5):
        return {"success": False, "records": [], "error": "not found"}

    async def fake_whois(args, timeout):
        return {"success": True, "stdout": "Registrant Email: admin@example.com\nAbuse Email: abuse@example.com", "stderr": "", "returncode": 0, "error": None}

    class FakeResponse:
        text = '<html><a href="mailto:contact@example.com">Contact us</a></html>'

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("app.modules.osint.email_harvester.query", new=fake_query), \
         patch("app.modules.osint.email_harvester.run_subprocess", new=fake_whois), \
         patch("httpx.AsyncClient.get", new=fake_get):
        result = await EmailHarvesterModule().run(EmailHarvesterModule.Input(domain="example.com"))

    addresses = {f.address for f in result.found}
    assert "admin@example.com" in addresses
    assert "abuse@example.com" in addresses
    assert "contact@example.com" in addresses
    contact_entry = next(f for f in result.found if f.address == "contact@example.com")
    assert contact_entry.source == "website"


@pytest.mark.asyncio
async def test_deduplicates_addresses_across_sources():
    from app.modules.osint.email_harvester import EmailHarvesterModule

    async def fake_query(name, rtype, timeout=5):
        if "_dmarc" in name:
            return {"success": True, "records": ["v=DMARC1; rua=mailto:same@example.com"], "error": None}
        return {"success": False, "records": [], "error": "not found"}

    async def fake_whois(args, timeout):
        return {"success": True, "stdout": "Contact: same@example.com", "stderr": "", "returncode": 0, "error": None}

    class FakeResponse:
        text = "<html>nothing</html>"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("app.modules.osint.email_harvester.query", new=fake_query), \
         patch("app.modules.osint.email_harvester.run_subprocess", new=fake_whois), \
         patch("httpx.AsyncClient.get", new=fake_get):
        result = await EmailHarvesterModule().run(EmailHarvesterModule.Input(domain="example.com"))

    matches = [f for f in result.found if f.address == "same@example.com"]
    assert len(matches) == 1


@pytest.mark.asyncio
async def test_no_findings_returns_empty_list_not_error():
    from app.modules.osint.email_harvester import EmailHarvesterModule

    async def fake_query(name, rtype, timeout=5):
        return {"success": False, "records": [], "error": "not found"}

    async def fake_whois(args, timeout):
        return {"success": False, "stdout": "", "stderr": "", "returncode": 1, "error": None}

    class FakeResponse:
        text = "<html>nothing here</html>"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("app.modules.osint.email_harvester.query", new=fake_query), \
         patch("app.modules.osint.email_harvester.run_subprocess", new=fake_whois), \
         patch("httpx.AsyncClient.get", new=fake_get):
        result = await EmailHarvesterModule().run(EmailHarvesterModule.Input(domain="clean.example.com"))

    assert result.success is True
    assert result.found == []

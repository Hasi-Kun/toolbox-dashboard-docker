"""Tests fuer CVE Lookup. Die Erreichbarkeit der echten NVD-API wurde
zusaetzlich live geprueft (Fehlerbehandlung bei Nichterreichbarkeit) --
hier die Parsing-Logik mit realistischen Daten."""

from unittest.mock import patch

import pytest

from app.modules.osint.cve_lookup import CveLookupModule


def test_rejects_invalid_cve_format():
    mod = CveLookupModule()
    with pytest.raises(Exception):
        mod.Input(cve_id="not-a-cve")


def test_normalizes_lowercase_cve_id():
    mod = CveLookupModule()
    inp = mod.Input(cve_id="cve-2021-44228")
    assert inp.cve_id == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_parses_realistic_nvd_response():
    fake_response = {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2024-01-01T00:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI RCE."},
                    {"lang": "es", "value": "Descripcion en espanol."},
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}],
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
                "references": [{"url": "https://logging.apache.org/security.html", "source": "security@apache.org"}],
            }
        }],
    }

    class FakeResponse:
        status_code = 200

        def json(self):
            return fake_response

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    mod = CveLookupModule()
    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(cve_id="CVE-2021-44228"))

    assert out.found is True
    assert out.description == "Apache Log4j2 JNDI RCE."
    assert out.cvss[0].base_score == 10.0
    assert out.cvss[0].base_severity == "CRITICAL"
    assert out.cwe_ids == ["CWE-502"]
    assert len(out.references) == 1


@pytest.mark.asyncio
async def test_handles_not_found():
    class FakeResponse:
        status_code = 200

        def json(self):
            return {"totalResults": 0, "vulnerabilities": []}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    mod = CveLookupModule()
    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(cve_id="CVE-1999-99999"))

    assert out.found is False
    assert out.error is not None


@pytest.mark.asyncio
async def test_handles_rate_limit_response():
    class FakeResponse:
        status_code = 429

        def json(self):
            return {}

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    mod = CveLookupModule()
    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(cve_id="CVE-2021-44228"))

    assert out.found is False
    assert "Rate-Limit" in out.error


@pytest.mark.asyncio
async def test_handles_unreachable_api_gracefully():
    async def fake_get(self, url, **kwargs):
        raise __import__("httpx").ConnectError("no route")

    mod = CveLookupModule()
    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(cve_id="CVE-2021-44228"))

    assert out.found is False
    assert out.error is not None


@pytest.mark.asyncio
async def test_prefers_english_description():
    fake_response = {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "es", "value": "Solo espanol disponible"},
                    {"lang": "en", "value": "English description"},
                ],
                "metrics": {}, "weaknesses": [], "references": [],
            }
        }],
    }

    class FakeResponse:
        status_code = 200

        def json(self):
            return fake_response

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    mod = CveLookupModule()
    with patch("httpx.AsyncClient.get", new=fake_get):
        out = await mod.run(mod.Input(cve_id="CVE-2021-44228"))

    assert out.description == "English description"

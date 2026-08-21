"""Tests fuer den JSON-Formatter und den Exponierte-Dateien-Checker."""

from unittest.mock import patch

import pytest
from pydantic import ValidationError


# --- JSON Formatter ----------------------------------------------------------

def test_json_formatter_registered():
    from app.modules import get_registry

    assert "json-formatter" in get_registry()


def test_json_formatter_rejects_empty_input():
    from app.modules.converter.json_formatter import JsonFormatterModule

    with pytest.raises(ValidationError):
        JsonFormatterModule.Input(json_text="   ")


@pytest.mark.asyncio
async def test_json_formatter_pretty_prints_valid_json():
    from app.modules.converter.json_formatter import JsonFormatterModule

    result = await JsonFormatterModule().run(JsonFormatterModule.Input(json_text='{"b":2,"a":1}', sort_keys=True))
    assert result.valid is True
    assert '"a": 1' in result.formatted
    assert result.formatted.index('"a"') < result.formatted.index('"b"')


@pytest.mark.asyncio
async def test_json_formatter_minifies():
    from app.modules.converter.json_formatter import JsonFormatterModule

    result = await JsonFormatterModule().run(JsonFormatterModule.Input(json_text='{"a": 1, "b": [1, 2, 3]}', mode="minify"))
    assert result.valid is True
    assert " " not in result.formatted
    assert result.formatted == '{"a":1,"b":[1,2,3]}'


@pytest.mark.asyncio
async def test_json_formatter_reports_error_location():
    from app.modules.converter.json_formatter import JsonFormatterModule

    result = await JsonFormatterModule().run(JsonFormatterModule.Input(json_text='{"a": 1,}'))
    assert result.valid is False
    assert result.error_line is not None
    assert result.error_column is not None


@pytest.mark.asyncio
async def test_json_formatter_counts_keys():
    from app.modules.converter.json_formatter import JsonFormatterModule

    result = await JsonFormatterModule().run(JsonFormatterModule.Input(json_text='{"a": 1, "b": {"c": 2, "d": 3}}'))
    assert result.key_count == 4  # a, b, c, d


# --- Exposed Files Checker ----------------------------------------------------

def test_exposed_files_checker_registered():
    from app.modules import get_registry

    registry = get_registry()
    assert "exposed-files-checker" in registry
    assert registry["exposed-files-checker"].category == "security"


def test_exposed_files_checker_rejects_invalid_domain():
    from app.modules.security.exposed_files_checker import ExposedFilesCheckerModule

    with pytest.raises(ValidationError):
        ExposedFilesCheckerModule.Input(domain="not a domain; rm -rf /")


@pytest.mark.asyncio
async def test_exposed_files_checker_finds_real_exposure():
    from app.modules.security.exposed_files_checker import ExposedFilesCheckerModule

    class FakeResponse:
        def __init__(self, status_code, text=""):
            self.status_code = status_code
            self.text = text
            self.content = text.encode()

    async def fake_get(self, url, **kwargs):
        if url.endswith("/.env"):
            return FakeResponse(200, "DB_PASSWORD=supergeheim123\nAPI_KEY=abcdef")
        return FakeResponse(404, "Not Found")

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await ExposedFilesCheckerModule().run(ExposedFilesCheckerModule.Input(domain="vulnerable.example.com"))

    paths_found = [e.path for e in result.exposed]
    assert ".env" in paths_found


@pytest.mark.asyncio
async def test_exposed_files_checker_avoids_spa_false_positives():
    """Regressionstest: eine SPA/CMS, die auf JEDEN Pfad mit identischem
    200-OK antwortet, darf NICHT jeden geprueften Pfad als 'exponiert'
    melden -- das war das zentrale Entwurfsproblem bei diesem Tool."""
    from app.modules.security.exposed_files_checker import ExposedFilesCheckerModule

    class FakeResponse:
        def __init__(self, status_code, text=""):
            self.status_code = status_code
            self.text = text
            self.content = text.encode()

    async def fake_get(self, url, **kwargs):
        return FakeResponse(200, "<html>Immer dieselbe generische Seite, gleiche Laenge</html>")

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await ExposedFilesCheckerModule().run(ExposedFilesCheckerModule.Input(domain="spa.example.com"))

    assert len(result.exposed) == 0


@pytest.mark.asyncio
async def test_exposed_files_checker_no_findings_on_clean_site():
    from app.modules.security.exposed_files_checker import ExposedFilesCheckerModule

    class FakeResponse:
        def __init__(self, status_code, text=""):
            self.status_code = status_code
            self.text = text
            self.content = text.encode()

    async def fake_get(self, url, **kwargs):
        return FakeResponse(404, "Not Found")

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await ExposedFilesCheckerModule().run(ExposedFilesCheckerModule.Input(domain="clean.example.com"))

    assert result.success is True
    assert result.exposed == []

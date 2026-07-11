"""Tests fuer den Reflected-Input-Checker (passiver XSS-Indikator) --
bewusst als sichere Alternative zu einem echten 'XSS-Exploiter' gebaut,
der Daten von echten Website-Besuchern abgreifen wuerde.
"""

import urllib.parse
from unittest.mock import patch

import pytest
from pydantic import ValidationError


def test_reflected_input_checker_registered():
    from app.modules import get_registry

    assert "reflected-input-checker" in get_registry()
    assert get_registry()["reflected-input-checker"].category == "security"


def test_reflected_input_checker_rejects_invalid_url():
    from app.modules.security.reflected_input_checker import ReflectedInputCheckerModule

    with pytest.raises(ValidationError):
        ReflectedInputCheckerModule.Input(url="not a url; rm -rf /")


@pytest.mark.asyncio
async def test_detects_unescaped_reflection():
    from app.modules.security.reflected_input_checker import ReflectedInputCheckerModule

    class FakeResponse:
        def __init__(self, text):
            self.text = text

    async def fake_get(self, url, **kwargs):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if "q" in params:
            return FakeResponse(f"<div>Results for: {params['q'][0]}</div>")
        return FakeResponse("<html>no reflection</html>")

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await ReflectedInputCheckerModule().run(ReflectedInputCheckerModule.Input(url="https://vulnerable.example.com/search"))

    reflected_params = [p.parameter for p in result.potentially_reflected]
    assert "q" in reflected_params
    assert len(result.potentially_reflected) == 1


@pytest.mark.asyncio
async def test_no_false_positive_on_properly_escaped_site():
    from app.modules.security.reflected_input_checker import ReflectedInputCheckerModule

    class FakeResponse:
        text = "<html>nothing reflected here at all</html>"

    async def fake_get(self, url, **kwargs):
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        result = await ReflectedInputCheckerModule().run(ReflectedInputCheckerModule.Input(url="https://safe.example.com"))

    assert result.potentially_reflected == []


@pytest.mark.asyncio
async def test_never_constructs_executable_script_payload():
    """Regressionstest, der die Kernabgrenzung zu einem echten 'XSS-
    Exploiter' absichert: der verwendete Marker darf niemals ein
    ausfuehrbares <script>-Tag oder Event-Handler-Attribut enthalten --
    nur harmlose Sonderzeichen zur Erkennung fehlender Kodierung."""
    from app.modules.security.reflected_input_checker import ReflectedInputCheckerModule

    captured_markers = []

    class FakeResponse:
        text = ""

    async def fake_get(self, url, **kwargs):
        marker = url.split("=", 1)[1]
        captured_markers.append(urllib.parse.unquote(marker))
        return FakeResponse()

    with patch("httpx.AsyncClient.get", new=fake_get):
        await ReflectedInputCheckerModule().run(ReflectedInputCheckerModule.Input(url="https://example.com"))

    for marker in captured_markers:
        assert "<script" not in marker.lower()
        assert "onerror" not in marker.lower()
        assert "onload" not in marker.lower()
        assert "javascript:" not in marker.lower()

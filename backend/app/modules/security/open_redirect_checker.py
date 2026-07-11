"""Prueft eine URL auf offene Weiterleitungen (Open Redirect) -- haengt
gaengige Redirect-Parameternamen mit einem harmlosen, eindeutig
erkennbaren Test-Ziel an und prueft, ob der Server tatsaechlich dorthin
weiterleitet. Rein passiv: das Test-Ziel ist eine bekannte, harmlose
Domain, es wird nichts Schaedliches uebertragen.
"""

import asyncio
import urllib.parse

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

# Bewusst ein offensichtlich fremdes, aber voellig harmloses Test-Ziel --
# example.com ist fuer genau solche Zwecke von der IANA reserviert.
_PROBE_TARGET = "https://example.com/toolbox-redirect-probe"

_COMMON_REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnUrl", "return_url", "continue", "dest", "destination", "goto",
    "target", "r", "u", "callback", "forward",
]


class RedirectProbeResult(BaseModel):
    parameter: str
    tested_url: str
    redirected_to_probe_target: bool
    final_url: str | None = None


@register_module
class OpenRedirectCheckerModule(ToolModule):
    slug = "open-redirect-checker"
    category = "security"
    name = "Open-Redirect-Checker"
    description = (
        "Haengt gaengige Redirect-Parameternamen (redirect, url, next, return, ...) mit einem "
        "harmlosen Test-Ziel an eine URL an und prueft, ob der Server tatsaechlich dorthin "
        "weiterleitet -- die klassische 'Open Redirect'-Schwachstelle, oft fuer Phishing missbraucht."
    )
    is_active_scan = False
    timeout_seconds = 20

    class Input(BaseModel):
        url: str

        @field_validator("url")
        @classmethod
        def validate_url(cls, v: str) -> str:
            v = v.strip()
            if not v.startswith(("http://", "https://")):
                v = f"https://{v}"
            host = v.split("://", 1)[1].split("/")[0].split("?")[0]
            if not (is_valid_hostname(host) or is_valid_ip(host)):
                raise ValueError("Ungueltige URL")
            return v

    class Output(BaseModel):
        url: str
        success: bool
        vulnerable_parameters: list[RedirectProbeResult] = []
        parameters_tested: int = 0
        error: str | None = None

    async def run(self, data: Input) -> Output:
        separator = "&" if "?" in data.url else "?"

        async def probe_one(client: httpx.AsyncClient, param: str) -> RedirectProbeResult:
            test_url = f"{data.url}{separator}{param}={urllib.parse.quote(_PROBE_TARGET, safe='')}"
            try:
                response = await client.get(test_url, headers={"User-Agent": "Toolbox-Redirect-Check/1.0"})
                final_url = str(response.url)
                final_host = urllib.parse.urlsplit(final_url).netloc
                # WICHTIG: nur als verwundbar zaehlen, wenn tatsaechlich
                # mindestens EIN echter Redirect stattfand (response.history
                # nicht leer) UND die Anfrage am Ende wirklich bei
                # example.com gelandet ist. Ein reiner Substring-Check auf
                # die volle URL waere IMMER wahr gewesen -- der Test-String
                # steckt ja selbst als Query-Parameter-WERT in der
                # angefragten URL drin, auch wenn der Server gar nicht
                # weitergeleitet hat.
                redirected = bool(response.history) and final_host == "example.com"
                return RedirectProbeResult(parameter=param, tested_url=test_url, redirected_to_probe_target=redirected, final_url=final_url)
            except httpx.HTTPError as exc:
                return RedirectProbeResult(parameter=param, tested_url=test_url, redirected_to_probe_target=False, final_url=f"Fehler: {exc}")

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, max_redirects=5) as client:
                results = await asyncio.gather(*(probe_one(client, p) for p in _COMMON_REDIRECT_PARAMS))
        except Exception as exc:  # noqa: BLE001
            return self.Output(url=data.url, success=False, error=str(exc))

        vulnerable = [r for r in results if r.redirected_to_probe_target]
        return self.Output(url=data.url, success=True, vulnerable_parameters=vulnerable, parameters_tested=len(results))

"""Prueft eine URL auf potenzielle Reflected-XSS-Einstiegspunkte -- rein
PASSIV: haengt an jeden GET-Parameter einen harmlosen, eindeutigen
Marker-String mit HTML-Sonderzeichen an und prueft, ob dieser
UNVERAENDERT (also ungeescaped) in der Antwort erscheint. Das ist der
Industriestandard fuer passive XSS-Indikator-Checks (z.B. Burp Suite's
passiver Scanner) -- es wird NIEMALS echter JavaScript-Code ausgefuehrt,
niemand angegriffen und keine Daten von echten Nutzern abgegriffen.
Zeigt nur: "dieser Parameter wird ungeprueft in die Seite uebernommen".

Bewusst NICHT gebaut: ein Tool, das eine tatsaechliche Angriffs-Payload
generiert, um bei echten Website-Besuchern Cookies/Tastatureingaben/
Screenshots abzugreifen -- das waere eine aktive Angriffsinfrastruktur
gegen echte, nicht einwilligende Dritte, kein Erkennungswerkzeug mehr.
"""

import asyncio
import secrets
import urllib.parse

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

_COMMON_PARAMS = [
    "q", "query", "search", "s", "name", "id", "input", "text", "message",
    "comment", "keyword", "term", "value", "data", "content", "title",
]


class ReflectedParamResult(BaseModel):
    parameter: str
    reflected_unescaped: bool
    context_snippet: str | None = None


@register_module
class ReflectedInputCheckerModule(ToolModule):
    slug = "reflected-input-checker"
    category = "security"
    name = "Reflected-Input-Checker (XSS-Indikator)"
    description = (
        "Prueft GET-Parameter auf potenzielle Reflected-XSS-Einstiegspunkte -- haengt einen "
        "harmlosen, eindeutigen Marker mit HTML-Sonderzeichen an und prueft, ob er ungeescaped in "
        "der Antwort landet. Rein passiv: es wird nie echter Code ausgefuehrt oder jemand "
        "angegriffen, nur ein Hinweis auf fehlende Ausgabe-Kodierung."
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
        parameters_tested: int = 0
        potentially_reflected: list[ReflectedParamResult] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        # Eindeutiger, harmloser Marker pro Lauf -- HTML-Sonderzeichen
        # drin (< > " '), aber kein ausfuehrbarer Code, kein <script>-Tag,
        # keine Angriffs-Payload. Nur ob GENAU DIESER String ungeescaped
        # zurueckkommt wird geprueft.
        marker = f"tbx{secrets.token_hex(4)}<>\"'"
        separator = "&" if "?" in data.url else "?"

        async def probe_one(client: httpx.AsyncClient, param: str) -> ReflectedParamResult:
            test_url = f"{data.url}{separator}{param}={urllib.parse.quote(marker)}"
            try:
                response = await client.get(test_url, headers={"User-Agent": "Toolbox-Reflected-Input-Check/1.0"})
            except httpx.HTTPError:
                return ReflectedParamResult(parameter=param, reflected_unescaped=False)

            if marker in response.text:
                idx = response.text.find(marker)
                snippet = response.text[max(0, idx - 40):idx + len(marker) + 40]
                return ReflectedParamResult(parameter=param, reflected_unescaped=True, context_snippet=snippet)
            return ReflectedParamResult(parameter=param, reflected_unescaped=False)

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                results = await asyncio.gather(*(probe_one(client, p) for p in _COMMON_PARAMS))
        except Exception as exc:  # noqa: BLE001
            return self.Output(url=data.url, success=False, error=str(exc))

        reflected = [r for r in results if r.reflected_unescaped]
        return self.Output(url=data.url, success=True, parameters_tested=len(results), potentially_reflected=reflected)

"""Prueft auf klassische CORS-Fehlkonfigurationen: Origin-Reflection ohne
Allowlist, kombiniert mit Access-Control-Allow-Credentials -- das
klassische Muster, das es jeder beliebigen fremden Seite erlaubt, im
Namen eingeloggter Nutzer authentifizierte Anfragen zu stellen.
"""

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip
from app.modules.security.common import build_client

# Bewusst ein offensichtlich fremd wirkender Test-Origin -- wenn der
# Server GENAU DIESEN Wert reflektiert, reflektiert er JEDEN Origin.
_PROBE_ORIGIN = "https://cors-probe-toolbox-test.example"


@register_module
class CorsMisconfigCheckerModule(ToolModule):
    slug = "cors-checker"
    category = "security"
    name = "CORS-Fehlkonfigurations-Checker"
    description = (
        "Sendet eine Anfrage mit einem offensichtlich fremden Test-Origin und prueft, ob der Server "
        "ihn unreflektiert als Access-Control-Allow-Origin zurueckgibt -- besonders kritisch in "
        "Kombination mit Access-Control-Allow-Credentials (erlaubt dann JEDER Seite authentifizierte "
        "Anfragen im Namen eingeloggter Nutzer)."
    )
    is_active_scan = False
    timeout_seconds = 10

    class Input(BaseModel):
        url: str

        @field_validator("url")
        @classmethod
        def validate_url(cls, v: str) -> str:
            v = v.strip()
            if not v.startswith(("http://", "https://")):
                v = f"https://{v}"
            host = v.split("://", 1)[1].split("/")[0]
            if not (is_valid_hostname(host) or is_valid_ip(host)):
                raise ValueError("Ungueltige URL")
            return v

    class Output(BaseModel):
        url: str
        success: bool
        status_code: int | None = None
        acao_header: str | None = None
        acac_header: str | None = None
        reflects_arbitrary_origin: bool = False
        allows_credentials: bool = False
        risk: str | None = None  # "kritisch" | "niedrig" | "keine"
        detail: str | None = None
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            async with build_client(timeout=self.timeout_seconds) as client:
                response = await client.get(data.url, headers={"Origin": _PROBE_ORIGIN})
        except httpx.HTTPError as exc:
            return self.Output(url=data.url, success=False, error=str(exc))

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        acao = headers_lower.get("access-control-allow-origin")
        acac = headers_lower.get("access-control-allow-credentials")

        reflects_arbitrary = acao == _PROBE_ORIGIN
        allows_credentials = (acac or "").strip().lower() == "true"

        if reflects_arbitrary and allows_credentials:
            risk = "kritisch"
            detail = (
                "Der Server reflektiert JEDEN Origin (auch einen frei erfundenen Test-Wert) UND erlaubt "
                "Credentials -- jede beliebige Webseite kann im Browser eines eingeloggten Nutzers "
                "authentifizierte Anfragen an diese API stellen und die Antwort auslesen."
            )
        elif reflects_arbitrary:
            risk = "niedrig"
            detail = (
                "Der Server reflektiert JEDEN Origin, aber ohne Allow-Credentials -- weniger kritisch "
                "(keine Cookies/Auth-Header werden mitgesendet), aber eine explizite Allowlist waere sauberer."
            )
        elif acao == "*" and allows_credentials:
            risk = "kritisch"
            detail = (
                "Access-Control-Allow-Origin: * kombiniert mit Allow-Credentials: true -- diese "
                "Kombination ist laut Spezifikation eigentlich ungueltig (Browser lehnen sie ab), "
                "deutet aber auf eine unsaubere CORS-Konfiguration hin."
            )
        elif acao is None:
            risk = "keine"
            detail = "Kein Access-Control-Allow-Origin-Header gefunden -- Cross-Origin-Anfragen werden vom Browser blockiert."
        else:
            risk = "keine"
            detail = f"Origin wird nicht reflektiert (Allow-Origin: {acao}) -- keine offensichtliche Fehlkonfiguration."

        return self.Output(
            url=data.url, success=True, status_code=response.status_code,
            acao_header=acao, acac_header=acac,
            reflects_arbitrary_origin=reflects_arbitrary, allows_credentials=allows_credentials,
            risk=risk, detail=detail,
        )

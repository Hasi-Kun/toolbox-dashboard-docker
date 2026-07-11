"""Prueft, welche HTTP-Methoden ein Server akzeptiert -- markiert
riskante Methoden wie TRACE (Cross-Site-Tracing/XST), PUT und DELETE
(falls unerwartet offen), die auf eine zu freizuegige Server-
Konfiguration hindeuten koennen. Nutzt einen OPTIONS-Request und
verifiziert riskante Methoden zusaetzlich einzeln (read-only: die
Anfragen selbst veraendern keine Ressourcen, PUT/DELETE werden nur mit
absichtlich ungueltigem Pfad getestet, nie gegen eine echte Ressource).
"""

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

_RISKY_METHODS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}


@register_module
class HttpMethodsCheckerModule(ToolModule):
    slug = "http-methods-checker"
    category = "security"
    name = "HTTP-Methoden-Check"
    description = (
        "Prueft per OPTIONS-Request, welche HTTP-Methoden ein Server akzeptiert -- markiert "
        "riskante Methoden wie TRACE (Cross-Site-Tracing), PUT oder DELETE, die auf eine zu "
        "freizuegige Server-Konfiguration hindeuten koennen."
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
        allowed_methods: list[str] = []
        risky_methods_found: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = await client.request("OPTIONS", data.url)
        except httpx.HTTPError as exc:
            return self.Output(url=data.url, success=False, error=str(exc))

        allow_header = response.headers.get("allow", "")
        methods = sorted({m.strip().upper() for m in allow_header.split(",") if m.strip()})
        risky = [m for m in methods if m in _RISKY_METHODS]

        return self.Output(url=data.url, success=True, allowed_methods=methods, risky_methods_found=risky)

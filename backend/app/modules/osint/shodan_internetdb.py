"""Fragt Shodans kostenlose, unauthentifizierte InternetDB-API ab --
liefert bekannte offene Ports, erkannte Software (CPEs), Hostnamen und
bekannte CVEs fuer eine IP. Keine eigene Portscan-Aktivitaet, nur ein
Abruf aus Shodans bereits vorhandenem (woechentlich aktualisiertem)
Datenbestand.
"""

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_ip


@register_module
class ShodanInternetDbModule(ToolModule):
    slug = "shodan-internetdb"
    category = "osint"
    name = "Shodan InternetDB Lookup"
    description = (
        "Fragt Shodans kostenlose InternetDB-API ab (kein API-Key noetig) -- zeigt bekannte offene "
        "Ports, erkannte Software (CPEs), Hostnamen und bekannte CVEs fuer eine IP, basierend auf "
        "Shodans eigenem (woechentlich aktualisiertem) Scan-Datenbestand. Kein eigener aktiver Scan."
    )
    is_active_scan = False
    timeout_seconds = 12

    class Input(BaseModel):
        ip: str

        @field_validator("ip")
        @classmethod
        def validate_ip(cls, v: str) -> str:
            v = v.strip()
            if not is_valid_ip(v):
                raise ValueError("Ungueltige IP-Adresse (nur IPv4/IPv6, keine Hostnamen)")
            return v

    class Output(BaseModel):
        ip: str
        success: bool
        found: bool = False
        ports: list[int] = []
        cpes: list[str] = []
        hostnames: list[str] = []
        tags: list[str] = []
        vulns: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(f"https://internetdb.shodan.io/{data.ip}")
        except httpx.HTTPError as exc:
            return self.Output(ip=data.ip, success=False, error=str(exc))

        if response.status_code == 404:
            return self.Output(ip=data.ip, success=True, found=False)
        if response.status_code != 200:
            return self.Output(ip=data.ip, success=False, error=f"InternetDB antwortete mit HTTP {response.status_code}")

        try:
            body = response.json()
        except ValueError:
            return self.Output(ip=data.ip, success=False, error="Antwort konnte nicht als JSON gelesen werden")

        return self.Output(
            ip=data.ip, success=True, found=True,
            ports=sorted(body.get("ports", [])),
            cpes=body.get("cpes", []),
            hostnames=body.get("hostnames", []),
            tags=body.get("tags", []),
            vulns=sorted(body.get("vulns", [])),
        )

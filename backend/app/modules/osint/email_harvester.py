"""Sammelt oeffentlich sichtbare E-Mail-Adressen fuer eine Domain aus
mehreren OSINT-Quellen: DMARC-RUA/RUF-Adressen, WHOIS-Kontaktdaten, und
mailto:-Links auf der eigenen Startseite.

WICHTIG (bewusste Abgrenzung): das ist KEIN Leak-Datenbank-Scanner --
eine echte "durchsuche Have-I-Been-Pwned & Co. nach allen Adressen
dieser Domain"-Funktion gibt es bei HIBP nur mit verifizierter Domain
und kostenpflichtiger Enterprise-API, nicht frei nutzbar. Dieses Tool
sammelt stattdessen, was ueber eine Domain OHNEHIN oeffentlich sichtbar
ist (DNS-Eintraege, WHOIS, die eigene Website) -- nuetzlich, um zu
sehen, welche E-Mail-Adressen ueberhaupt im Umlauf sind, bevor man
gezielt einzelne davon z.B. mit dem Passwort-Leak-Check prueft.
"""

import asyncio
import re

import httpx
from pydantic import BaseModel, field_validator

from app.modules.dns.common import is_valid_hostname, query
from app.modules.base import ToolModule, register_module
from app.modules.network.common import run_subprocess

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_MAILTO_RE = re.compile(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', re.IGNORECASE)


class FoundEmail(BaseModel):
    address: str
    source: str  # "dmarc" | "whois" | "website"


@register_module
class EmailHarvesterModule(ToolModule):
    slug = "email-harvester"
    category = "osint"
    name = "E-Mail-Adressen-Finder"
    description = (
        "Sammelt oeffentlich sichtbare E-Mail-Adressen fuer eine Domain aus DMARC-Reporting-"
        "Adressen, WHOIS-Kontaktdaten und mailto:-Links auf der Startseite. Kein Leak-Datenbank-"
        "Scan (dafuer waere eine kostenpflichtige, domain-verifizierte API noetig) -- zeigt, welche "
        "Adressen ohnehin oeffentlich im Umlauf sind."
    )
    is_active_scan = False
    timeout_seconds = 20

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        success: bool
        found: list[FoundEmail] = []
        sources_checked: list[str] = []
        error: str | None = None

    async def _from_dmarc(self, domain: str) -> list[FoundEmail]:
        result = await query(f"_dmarc.{domain}", "TXT", timeout=6)
        if result.get("error") or not result.get("records"):
            return []
        found = []
        for record in result["records"]:
            for match in _EMAIL_RE.findall(record):
                found.append(FoundEmail(address=match, source="dmarc"))
        return found

    async def _from_whois(self, domain: str) -> list[FoundEmail]:
        result = await run_subprocess(["whois", domain], timeout=8)
        text = result.get("stdout", "")
        return [FoundEmail(address=m, source="whois") for m in set(_EMAIL_RE.findall(text))]

    async def _from_website(self, domain: str) -> list[FoundEmail]:
        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                response = await client.get(f"https://{domain}/", headers={"User-Agent": "Toolbox-Email-Harvester/1.0"})
        except httpx.HTTPError:
            return []
        html = response.text[:1_000_000]
        return [FoundEmail(address=m, source="website") for m in set(_MAILTO_RE.findall(html))]

    async def run(self, data: Input) -> Output:
        try:
            dmarc_emails, whois_emails, website_emails = await asyncio.gather(
                self._from_dmarc(data.domain), self._from_whois(data.domain), self._from_website(data.domain),
            )
        except Exception as exc:  # noqa: BLE001
            return self.Output(domain=data.domain, success=False, error=str(exc))

        all_found = dmarc_emails + whois_emails + website_emails
        # Nach Adresse deduplizieren, aber die erste gefundene Quelle behalten
        seen: dict[str, FoundEmail] = {}
        for item in all_found:
            key = item.address.lower()
            if key not in seen:
                seen[key] = item

        return self.Output(
            domain=data.domain, success=True, found=list(seen.values()),
            sources_checked=["dmarc", "whois", "website"],
        )

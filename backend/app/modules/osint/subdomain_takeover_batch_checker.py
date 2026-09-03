"""Subdomain-Takeover-Batch-Check: wendet dieselbe Pruefung wie der
Einzel-Checker (subdomain_takeover_checker.py) auf eine ganze Liste von
Subdomains parallel an -- fuer den Alltag realistischer, da man selten
nur EINE Subdomain pruefen will, sondern typischerweise gleich alle
bekannten Subdomains einer Organisation (z.B. aus subdomain-
bruteforce oder der eigenen DNS-Zone).
"""

import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname
from app.modules.osint.subdomain_takeover_checker import SubdomainTakeoverCheckerModule, check_subdomain_takeover

MAX_SUBDOMAINS = 50
# Begrenzt gleichzeitig laufende Pruefungen, damit nicht 50 parallele
# HTTP-Requests auf einmal rausgehen (freundlicher gegenueber den
# gepruften Zielen UND den eigenen Netzwerk-Ressourcen).
_CONCURRENCY_LIMIT = 8


@register_module
class SubdomainTakeoverBatchCheckerModule(ToolModule):
    slug = "subdomain-takeover-batch-checker"
    category = "osint"
    name = "Subdomain-Takeover-Check (Mehrere)"
    description = (
        "Prueft eine Liste von Subdomains (eine pro Zeile) gleichzeitig auf Takeover-Anfaelligkeit -- "
        "dieselbe Pruefung wie der Einzel-Checker, aber fuer den realistischen Fall, dass man gleich "
        "alle bekannten Subdomains einer Organisation im Blick haben will."
    )
    is_active_scan = False
    timeout_seconds = 60

    class Input(BaseModel):
        subdomains: str  # Zeilenweise Liste, wird geparst

        @field_validator("subdomains")
        @classmethod
        def validate_subdomains(cls, v: str) -> str:
            entries = [line.strip().rstrip(".") for line in v.splitlines() if line.strip()]
            if not entries:
                raise ValueError("Mindestens eine Subdomain angeben")
            if len(entries) > MAX_SUBDOMAINS:
                raise ValueError(f"Maximal {MAX_SUBDOMAINS} Subdomains pro Durchlauf")
            invalid = [e for e in entries if not is_valid_hostname(e)]
            if invalid:
                raise ValueError(f"Ungueltige Hostnamen: {', '.join(invalid[:5])}")
            return v

    class Output(BaseModel):
        results: list["SubdomainTakeoverCheckerModule.Output"]
        checked_count: int
        potentially_vulnerable_count: int

    async def run(self, data: "SubdomainTakeoverBatchCheckerModule.Input") -> "SubdomainTakeoverBatchCheckerModule.Output":
        subdomains = [line.strip().rstrip(".") for line in data.subdomains.splitlines() if line.strip()]

        semaphore = asyncio.Semaphore(_CONCURRENCY_LIMIT)

        async def _check_one(subdomain: str) -> SubdomainTakeoverCheckerModule.Output:
            async with semaphore:
                return await check_subdomain_takeover(subdomain, timeout_seconds=15)

        results = await asyncio.gather(*(_check_one(s) for s in subdomains))

        return self.Output(
            results=list(results),
            checked_count=len(results),
            potentially_vulnerable_count=sum(1 for r in results if r.potentially_vulnerable),
        )

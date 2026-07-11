"""Modul-Registry-Pattern.

Jedes Tool (DNS Lookup, Port-Scan, Hash-Generator, ...) implementiert
`ToolModule`. Neue Module registrieren sich selbst über den
`@register_module`-Decorator -- der API-Router muss dafuer nicht
angefasst werden.

Beispiel fuer ein zukuenftiges Modul (Phase 2):

    @register_module
    class DnsLookupModule(ToolModule):
        slug = "dns-lookup"
        category = "dns"
        name = "DNS Lookup"
        description = "Loest A/AAAA/MX/TXT/... Records fuer eine Domain auf"
        is_active_scan = False  # liest nur, kein Traffic zum Zielsystem ausser DNS

        class Input(BaseModel):
            domain: str
            record_type: Literal["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]

        async def run(self, data: "DnsLookupModule.Input") -> dict:
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel

_REGISTRY: dict[str, type["ToolModule"]] = {}


class ToolModule(ABC):
    """Basisklasse fuer alle Tools."""

    slug: ClassVar[str]
    category: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str] = ""

    # Passive Module (Lookups) laufen im Backend selbst.
    # Aktive Module (Scans) MUESSEN is_active_scan = True setzen und werden
    # ausschliesslich ueber die Queue an toolbox-scanner delegiert.
    is_active_scan: ClassVar[bool] = False

    # Pro-Modul Timeout-Override; None = Settings-Default verwenden
    timeout_seconds: ClassVar[int | None] = None

    # Manche Module (z.B. SMTP-Debug, das echte Mails verschicken kann)
    # sind bewusst nur fuer Admins freigeschaltet, nicht fuer alle
    # eingeloggten Member. Default: fuer alle nutzbar.
    requires_admin: ClassVar[bool] = False

    # Nur fuer is_active_scan-Module gesetzt: der Template-Name in der
    # Scanner-Queue (siehe app/core/scan_queue.py). Ermoeglicht das
    # generische Polling-Muster (POST .../scan/start + GET .../scan/status/{job_id})
    # in app/api/v1/endpoints/tools.py, ohne dass jede lange Scan-Anfrage
    # eine einzelne, lange offene HTTP-Verbindung braucht (die sonst an
    # Reverse-Proxy- oder CDN-Timeouts wie bei Cloudflare scheitern kann).
    scan_template: ClassVar[str | None] = None

    # Fuer Tools, die sensible Eingaben entgegennehmen (z.B. ein zu
    # pruefendes Passwort) -- verhindert, dass die Eingabe in der
    # Tool-Ausfuehrungs-Historie (tool_executions-Tabelle) landet. Das
    # Ergebnis selbst wird trotzdem protokolliert, nur die Eingabe wird
    # durch einen Platzhalter ersetzt.
    redact_input_in_history: ClassVar[bool] = False

    class Input(BaseModel):
        pass

    class Output(BaseModel):
        pass

    @abstractmethod
    async def run(self, data: Input) -> Output:
        """Fuehrt das Modul aus. Muss innerhalb des Timeouts fertig sein."""
        raise NotImplementedError

    def build_scan_params(self, data: Input) -> dict:
        """Nur fuer is_active_scan-Module: baut das params-Dict, das an die
        Scanner-Queue uebergeben wird. Default: alle Input-Felder 1:1."""
        raise NotImplementedError

    def parse_scan_result(self, data: Input, raw: dict) -> Output:
        """Nur fuer is_active_scan-Module: wandelt das rohe Ergebnis vom
        Scanner-Worker in das typisierte Output-Modell um."""
        raise NotImplementedError

    @classmethod
    def metadata(cls) -> dict:
        return {
            "slug": cls.slug,
            "category": cls.category,
            "name": cls.name,
            "description": cls.description,
            "is_active_scan": cls.is_active_scan,
            "requires_admin": cls.requires_admin,
        }


def register_module(cls: type[ToolModule]) -> type[ToolModule]:
    if cls.slug in _REGISTRY:
        raise ValueError(f"Modul-Slug '{cls.slug}' ist bereits registriert.")
    _REGISTRY[cls.slug] = cls
    return cls


def get_registry() -> dict[str, type[ToolModule]]:
    return dict(_REGISTRY)


def list_modules_metadata() -> list[dict]:
    return [m.metadata() for m in _REGISTRY.values()]

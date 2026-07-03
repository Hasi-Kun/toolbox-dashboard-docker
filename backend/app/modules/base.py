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

    class Input(BaseModel):
        pass

    class Output(BaseModel):
        pass

    @abstractmethod
    async def run(self, data: Input) -> Output:
        """Fuehrt das Modul aus. Muss innerhalb des Timeouts fertig sein."""
        raise NotImplementedError

    @classmethod
    def metadata(cls) -> dict:
        return {
            "slug": cls.slug,
            "category": cls.category,
            "name": cls.name,
            "description": cls.description,
            "is_active_scan": cls.is_active_scan,
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

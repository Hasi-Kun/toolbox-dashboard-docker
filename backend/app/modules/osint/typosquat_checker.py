"""Erkennt Typosquatting-Domains -- generiert gaengige Tippfehler-
Varianten einer Domain (vertauschte/fehlende/verdoppelte Buchstaben,
Nachbartasten-Vertipper, haeufige TLD-Variationen) und prueft per DNS,
welche davon tatsaechlich registriert sind. Rein lokale Generierung +
DNS-Lookups, keine externe API noetig.
"""

import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

# Nachbartasten auf einer QWERTZ/QWERTY-Tastatur -- fuer Vertipper-Varianten.
_ADJACENT_KEYS = {
    "a": "qws", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qeas", "x": "zsdc", "y": "tghu", "z": "asx",
}
_COMMON_TLD_SWAPS = ["com", "net", "org", "info", "co", "io"]
MAX_VARIANTS = 60


def _generate_variants(domain: str) -> set[str]:
    if "." not in domain:
        return set()
    name, _, tld = domain.partition(".")
    variants: set[str] = set()

    # Buchstabe weglassen
    for i in range(len(name)):
        variants.add(name[:i] + name[i + 1 :] + "." + tld)

    # Benachbarte Buchstaben vertauschen (Transposition)
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        variants.add("".join(swapped) + "." + tld)

    # Buchstabe verdoppeln
    for i in range(len(name)):
        variants.add(name[: i + 1] + name[i] + name[i + 1 :] + "." + tld)

    # Nachbartaste statt echtem Buchstaben (Vertipper)
    for i, char in enumerate(name):
        for neighbor in _ADJACENT_KEYS.get(char, ""):
            variants.add(name[:i] + neighbor + name[i + 1 :] + "." + tld)

    # Haeufige TLD-Variationen
    for alt_tld in _COMMON_TLD_SWAPS:
        if alt_tld != tld:
            variants.add(f"{name}.{alt_tld}")

    variants.discard(domain)
    return variants


class TyposquatResult(BaseModel):
    domain: str
    registered: bool
    ip_addresses: list[str] = []


@register_module
class TyposquatCheckerModule(ToolModule):
    slug = "typosquat-checker"
    category = "osint"
    name = "Typosquatting-Checker"
    description = (
        "Generiert gaengige Tippfehler-Varianten einer Domain (vertauschte/fehlende/verdoppelte "
        "Buchstaben, Nachbartasten-Vertipper, haeufige TLD-Wechsel) und prueft per DNS, welche "
        "davon tatsaechlich registriert sind -- hilft, Phishing-/Typosquatting-Domains zu finden."
    )
    is_active_scan = False
    timeout_seconds = 20

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".").lower()
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        variants_checked: int
        registered_variants: list[TyposquatResult] = []

    async def run(self, data: Input) -> Output:
        variants = sorted(_generate_variants(data.domain))[:MAX_VARIANTS]

        async def check(variant: str) -> TyposquatResult | None:
            result = await query(variant, "A", timeout=4)
            if result["success"] and result["records"]:
                return TyposquatResult(domain=variant, registered=True, ip_addresses=result["records"])
            return None

        results = await asyncio.gather(*(check(v) for v in variants))
        registered = [r for r in results if r is not None]

        return self.Output(domain=data.domain, variants_checked=len(variants), registered_variants=registered)

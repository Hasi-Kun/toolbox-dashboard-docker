"""E-Mail-Adressen-zu-Domains-Leak-Finder: prueft eine Domain gegen
oeffentlich zugaengliche Leak-/Breach-Quellen.

WICHTIG (ehrlicher Umfang -- Recherche-Ergebnis): eine vollstaendige
Massen-Suche "alle E-Mail-Adressen von domain.com, die in Breaches
aufgetaucht sind" bietet Have I Been Pwned (HIBP) seit einigen Jahren
NICHT MEHR kostenlos an -- sowohl die Einzel-E-Mail- als auch die
Domain-weite Suche erfordern mittlerweile ein kostenpflichtiges
Abonnement (siehe haveibeenpwned.com/API/v3, Abschnitt "Authorisation").
Bewusst NICHT nachgebaut mit Scraping o.ae. -- das wuerde HIBPs Nutzungs-
bedingungen verletzen.

Was WEITERHIN komplett kostenlos und OHNE API-Key verfuegbar ist:
1. HIBPs oeffentlicher Breach-KATALOG (/api/v3/breaches, keine Auth
   noetig) -- die Liste ALLER bekannten Breaches inkl. der jeweils
   betroffenen Domain. Damit laesst sich pruefen, ob die angegebene
   Domain SELBST (als betroffener Dienst) in einem bekannten Breach
   auftaucht.
2. Vorschlaege fuer manuelle Recherche auf Paste-/Leak-Sites (site:-
   Suchanfragen fuer die eigene Domain) -- reine Textgenerierung, keine
   automatisierte Suche (dieselbe Philosophie wie der bereits
   vorhandene google-dork-generator: liefert Ausgangspunkte fuer
   MANUELLE Recherche, fuehrt selbst nichts aus).
"""

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname

_PASTE_SITES = ["pastebin.com", "ghostbin.com", "throwbin.io", "controlc.com", "justpaste.it"]


@register_module
class EmailDomainLeakFinderModule(ToolModule):
    slug = "email-domain-leak-finder"
    category = "osint"
    name = "Email-Adressen-zu-Domains-Leak-Finder"
    description = (
        "Prueft, ob eine Domain im oeffentlichen Have-I-Been-Pwned-Breach-Katalog auftaucht (kostenlos, "
        "kein API-Key), plus Vorschlaege fuer manuelle Recherche auf Paste-Sites. Eine vollstaendige "
        "Massen-Suche nach geleakten E-Mail-Adressen EINER Domain bietet HIBP nicht mehr kostenlos an "
        "(erfordert seit einigen Jahren ein kostenpflichtiges Abo) -- das wird hier nicht nachgebaut."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".").lower()
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class BreachMatch(BaseModel):
        name: str
        title: str
        breach_date: str
        pwn_count: int
        data_classes: list[str]
        is_verified: bool

    class PasteSiteSuggestion(BaseModel):
        query: str
        site: str

    class Output(BaseModel):
        domain: str
        catalog_matches: list["EmailDomainLeakFinderModule.BreachMatch"] = []
        catalog_reachable: bool = True
        paste_site_suggestions: list["EmailDomainLeakFinderModule.PasteSiteSuggestion"]
        note: str

    async def run(self, data: "EmailDomainLeakFinderModule.Input") -> "EmailDomainLeakFinderModule.Output":
        catalog_matches: list[EmailDomainLeakFinderModule.BreachMatch] = []
        catalog_reachable = True

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(
                    "https://haveibeenpwned.com/api/v3/breaches",
                    headers={"User-Agent": "toolbox-self-hosted (email-domain-leak-finder)"},
                )
            if response.status_code == 200:
                breaches = response.json()
                for b in breaches:
                    if str(b.get("Domain", "")).lower() == data.domain:
                        catalog_matches.append(
                            self.BreachMatch(
                                name=b.get("Name", ""), title=b.get("Title", ""),
                                breach_date=b.get("BreachDate", ""), pwn_count=b.get("PwnCount", 0),
                                data_classes=b.get("DataClasses", []), is_verified=b.get("IsVerified", False),
                            )
                        )
            else:
                catalog_reachable = False
        except (httpx.HTTPError, ValueError):
            catalog_reachable = False

        suggestions = [
            self.PasteSiteSuggestion(query=f'site:{site} "@{data.domain}"', site=site) for site in _PASTE_SITES
        ]

        if catalog_matches:
            note = (
                f"{data.domain} taucht im HIBP-Breach-Katalog als betroffener Dienst auf -- Mitarbeiter-"
                f"E-Mails mit dieser Domain koennten in den gelisteten Breaches enthalten sein. Fuer eine "
                f"vollstaendige Liste betroffener Adressen ist ein kostenpflichtiges HIBP-Abo noetig."
            )
        elif not catalog_reachable:
            note = "HIBP-Breach-Katalog war nicht erreichbar -- keine Aussage zu bekannten Breaches moeglich."
        else:
            note = (
                f"{data.domain} taucht NICHT als eigener betroffener Dienst im HIBP-Katalog auf. Das sagt "
                f"NICHTS darueber aus, ob einzelne Mitarbeiter-E-Mails in ANDEREN Breaches (z.B. LinkedIn, "
                f"Adobe) enthalten sind -- dafuer waere eine E-Mail-weite Pruefung noetig, die HIBP nicht "
                f"mehr kostenlos anbietet. Die unten vorgeschlagenen Suchanfragen helfen bei der manuellen "
                f"Recherche auf Paste-Sites."
            )

        return self.Output(
            domain=data.domain, catalog_matches=catalog_matches, catalog_reachable=catalog_reachable,
            paste_site_suggestions=suggestions, note=note,
        )

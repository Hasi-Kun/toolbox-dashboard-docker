"""Prueft, ob eine Subdomain fuer eine 'Subdomain Takeover' anfaellig ist:
ein CNAME zeigt auf einen Cloud-Dienst (GitHub Pages, Heroku, S3, Azure,
etc.), aber der dortige Namensraum ist nicht (mehr) beansprucht -- dann
koennte jemand Fremdes ihn sich selbst registrieren und Inhalte unter der
eigenen Subdomain ausliefern. Rein DNS + ein einzelner HTTP-Request,
keine externe API noetig.
"""

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

# (CNAME-Suffix, Dienstname, Fingerabdruck-Text bei NICHT beanspruchtem Namensraum)
# Bewusst eine kuratierte, dokumentierte Liste bekannter Dienste --
# aehnlich der oeffentlich gepflegten "can-i-take-over-xyz"-Referenzlisten.
_TAKEOVER_SIGNATURES: list[tuple[str, str, str]] = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("herokudns.com", "Heroku", "No such app"),
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("s3-website", "AWS S3 (Website-Hosting)", "NoSuchBucket"),
    ("azurewebsites.net", "Azure App Service", "Error 404 - Web app not found"),
    ("cloudapp.net", "Azure Cloud Service", "Error 404 - Web app not found"),
    ("trafficmanager.net", "Azure Traffic Manager", "Error 404 - Web app not found"),
    ("readme.io", "ReadMe.io", "Project doesnt exist"),
    ("surge.sh", "Surge.sh", "project not found"),
    ("unbouncepages.com", "Unbounce", "The requested URL was not found on this server"),
    ("pantheonsite.io", "Pantheon", "The gods are wise"),
    ("cargocollective.com", "Cargo Collective", "404 Not Found"),
    ("statuspage.io", "Atlassian Statuspage", "You are being"),
    ("helpjuice.com", "Helpjuice", "We could not find what you"),
    ("helpscoutdocs.com", "Help Scout Docs", "No settings were found"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("wordpress.com", "WordPress.com", "Do you want to register"),
    ("fastly.net", "Fastly", "Fastly error: unknown domain"),
    ("ghost.io", "Ghost(Pro)", "The thing you were looking for is no longer here"),
    ("webflow.io", "Webflow", "The page you are looking for doesn't exist"),
    ("netlify.app", "Netlify", "Not Found - Request ID"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
]


@register_module
class SubdomainTakeoverCheckerModule(ToolModule):
    slug = "subdomain-takeover-checker"
    category = "osint"
    name = "Subdomain-Takeover-Checker"
    description = (
        "Prueft, ob eine Subdomain per CNAME auf einen Cloud-Dienst (GitHub Pages, Heroku, S3, "
        "Azure, Shopify, u.a.) zeigt, dessen Namensraum dort nicht mehr beansprucht ist -- ein "
        "klassisches Einfallstor fuer Subdomain-Uebernahmen durch Dritte."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        subdomain: str

        @field_validator("subdomain")
        @classmethod
        def validate_subdomain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltiger Hostname")
            return v

    class Output(BaseModel):
        subdomain: str
        cname_target: str | None = None
        matched_service: str | None = None
        potentially_vulnerable: bool = False
        http_check_error: str | None = None
        detail: str

    async def run(self, data: Input) -> Output:
        cname_result = await query(data.subdomain, "CNAME", timeout=6)
        if not cname_result["success"] or not cname_result["records"]:
            return self.Output(
                subdomain=data.subdomain, cname_target=None,
                detail="Kein CNAME-Record gefunden -- keine Subdomain-Takeover-Gefahr ueber diesen Vektor.",
            )

        cname_target = cname_result["records"][0].rstrip(".")
        matched = next(((suffix, service, fingerprint) for suffix, service, fingerprint in _TAKEOVER_SIGNATURES
                         if cname_target.endswith(suffix)), None)

        if matched is None:
            return self.Output(
                subdomain=data.subdomain, cname_target=cname_target,
                detail=f"CNAME zeigt auf '{cname_target}' -- kein bekannter Takeover-anfaelliger Dienst in unserer Signaturliste.",
            )

        suffix, service, fingerprint = matched
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds - 3, follow_redirects=True) as client:
                response = await client.get(f"https://{data.subdomain}", headers={"User-Agent": "Toolbox-Takeover-Check/1.0"})
        except httpx.HTTPError as exc:
            return self.Output(
                subdomain=data.subdomain, cname_target=cname_target, matched_service=service,
                http_check_error=str(exc),
                detail=f"CNAME zeigt auf {service} ({cname_target}), aber der HTTP-Check schlug fehl -- manuell pruefen.",
            )

        is_vulnerable = fingerprint.lower() in response.text.lower()
        return self.Output(
            subdomain=data.subdomain, cname_target=cname_target, matched_service=service,
            potentially_vulnerable=is_vulnerable,
            detail=(
                f"CNAME zeigt auf {service} ({cname_target}) UND der erwartete 'nicht beansprucht'-Text "
                f"wurde gefunden -- moeglicherweise uebernehmbar, manuell verifizieren!"
                if is_vulnerable else
                f"CNAME zeigt auf {service} ({cname_target}), aber der Namensraum scheint beansprucht "
                f"(kein 'nicht gefunden'-Fingerabdruck in der Antwort)."
            ),
        )

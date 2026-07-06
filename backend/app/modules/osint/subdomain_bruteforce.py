import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

# Kuratierte Liste haeufiger Subdomain-Praefixe -- bewusst rein DNS-basiert,
# keine externe API noetig (im Gegensatz zu certificate-transparency, das
# CT-Logs durchsucht). Findet Subdomains, die NIE ein Zertifikat bekommen
# haben und daher in CT-Logs nicht auftauchen (z.B. interne Dienste hinter
# einem internen CA oder ohne TLS).
COMMON_PREFIXES = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "mx", "ns1", "ns2",
    "ftp", "sftp", "vpn", "remote", "portal", "autodiscover", "api", "dev",
    "staging", "test", "admin", "secure", "cdn", "static", "assets", "m",
    "mobile", "app", "blog", "shop", "git", "gitlab", "jenkins", "jira",
    "confluence", "wiki", "docs", "support", "status", "monitor", "grafana",
    "kibana", "cpanel", "webdisk",
]


@register_module
class SubdomainBruteforceModule(ToolModule):
    slug = "subdomain-bruteforce"
    category = "osint"
    name = "Subdomain Bruteforce"
    description = (
        f"Prueft {len(COMMON_PREFIXES)} haeufige Subdomain-Praefixe per DNS-Aufloesung -- findet auch "
        "Subdomains, die nie ein oeffentliches Zertifikat hatten und daher in Certificate-Transparency-"
        "Logs nicht auftauchen. Rein DNS-basiert, keine externe API noetig."
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

    class FoundSubdomain(BaseModel):
        subdomain: str
        ip_addresses: list[str]

    class Output(BaseModel):
        domain: str
        checked_count: int
        found: list["SubdomainBruteforceModule.FoundSubdomain"] = []

    async def run(self, data: Input) -> Output:
        async def check(prefix: str) -> "SubdomainBruteforceModule.FoundSubdomain | None":
            fqdn = f"{prefix}.{data.domain}"
            result = await query(fqdn, "A", timeout=4)
            if result["success"] and result["records"]:
                return self.FoundSubdomain(subdomain=fqdn, ip_addresses=result["records"])
            return None

        results = await asyncio.gather(*(check(p) for p in COMMON_PREFIXES))
        found = [r for r in results if r is not None]

        return self.Output(domain=data.domain, checked_count=len(COMMON_PREFIXES), found=found)

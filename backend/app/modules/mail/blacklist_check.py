import asyncio
import ipaddress

import dns.asyncresolver
import dns.resolver
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

# Gaengige oeffentliche DNSBLs (DNS-based Blackhole Lists). Eine A-Antwort
# (typischerweise 127.0.0.x) bedeutet gelistet, NXDOMAIN bedeutet sauber.
_BLACKLISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
]


class BlacklistResult(BaseModel):
    blacklist: str
    listed: bool
    response: str | None = None


@register_module
class BlacklistCheckModule(ToolModule):
    slug = "blacklist-check"
    category = "mail"
    name = "Blacklist Check"
    description = (
        f"Prueft eine IP gegen {len(_BLACKLISTS)} bekannte DNSBLs (Spamhaus, SpamCop, Barracuda, SORBS). "
        "Hinweis: Spamhaus blockiert Anfragen von oeffentlichen DNS-Resolvern (z.B. Google DNS, Cloudflare) "
        "und liefert dann faelschlich 'nicht gelistet' zurueck -- fuer verlaessliche Spamhaus-Ergebnisse "
        "sollte der Server einen eigenen/ISP-Resolver statt eines oeffentlichen Resolvers nutzen."
    )
    is_active_scan = False
    timeout_seconds = 10

    class Input(BaseModel):
        target: str

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiges Ziel (Domain oder IP erwartet)")
            return v

    class Output(BaseModel):
        target: str
        resolved_ip: str | None = None
        results: list[BlacklistResult] = []
        listed_count: int = 0
        error: str | None = None

    async def run(self, data: Input) -> Output:
        ip = data.target
        if not is_valid_ip(ip):
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            try:
                answer = await resolver.resolve(data.target, "A")
                ip = answer[0].to_text()
            except Exception as exc:  # noqa: BLE001
                return self.Output(target=data.target, error=f"Konnte Domain nicht aufloesen: {exc}")

        try:
            reversed_ip = ".".join(reversed(ipaddress.IPv4Address(ip).exploded.split(".")))
        except ipaddress.AddressValueError:
            return self.Output(target=data.target, resolved_ip=ip, error="Blacklist-Check unterstuetzt aktuell nur IPv4")

        results = await asyncio.gather(*(self._check_one(bl, reversed_ip) for bl in _BLACKLISTS))
        listed_count = sum(1 for r in results if r.listed)

        return self.Output(target=data.target, resolved_ip=ip, results=results, listed_count=listed_count, error=None)

    @staticmethod
    async def _check_one(blacklist: str, reversed_ip: str) -> BlacklistResult:
        query_name = f"{reversed_ip}.{blacklist}"
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 4
        try:
            answer = await resolver.resolve(query_name, "A")
            return BlacklistResult(blacklist=blacklist, listed=True, response=answer[0].to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return BlacklistResult(blacklist=blacklist, listed=False)
        except Exception:  # noqa: BLE001 -- Timeout/Nameserver-Fehler zaehlen als "nicht pruefbar", nicht als gelistet
            return BlacklistResult(blacklist=blacklist, listed=False, response="nicht pruefbar (Timeout)")

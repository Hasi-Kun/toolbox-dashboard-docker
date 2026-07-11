"""Prueft, ob einer der autoritativen Nameserver einer Domain
faelschlicherweise einen Zone-Transfer (AXFR) an JEDEN erlaubt -- eine
klassische Fehlkonfiguration, die die komplette DNS-Zone (alle
Subdomains, interne Hostnamen etc.) gegenueber jedem offenlegt, der
danach fragt.
"""

import asyncio

import dns.exception
import dns.query
import dns.resolver
import dns.zone
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname


def _try_axfr(nameserver_ip: str, domain: str, timeout: float) -> dict:
    """Blockierender dnspython-Code -- ueber asyncio.to_thread aufgerufen."""
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver_ip, domain, timeout=timeout, lifetime=timeout))
        record_count = sum(len(node.rdatasets) for node in zone.nodes.values())
        # Nur eine Stichprobe der Namen zeigen (nicht die komplette Zone
        # ausgeben) -- reicht, um die Fehlkonfiguration zu belegen, ohne
        # das Tool selbst zu einem vollstaendigen Zone-Dump-Werkzeug zu machen.
        sample_names = sorted(str(name) for name in zone.nodes.keys())[:15]
        return {"vulnerable": True, "record_count": record_count, "sample_names": sample_names, "error": None}
    except (dns.exception.FormError, ConnectionRefusedError, OSError, dns.exception.Timeout):
        # FormError = Server hat AXFR sauber abgelehnt (das ist der GUTE Fall)
        return {"vulnerable": False, "record_count": 0, "sample_names": [], "error": None}
    except Exception as exc:  # noqa: BLE001
        return {"vulnerable": False, "record_count": 0, "sample_names": [], "error": str(exc)}


class NameserverAxfrResult(BaseModel):
    nameserver: str
    ip: str | None
    vulnerable: bool
    record_count: int = 0
    sample_names: list[str] = []
    error: str | None = None


@register_module
class ZoneTransferCheckModule(ToolModule):
    slug = "zone-transfer-check"
    category = "dns"
    name = "DNS-Zone-Transfer-Check (AXFR)"
    description = (
        "Prueft, ob einer der autoritativen Nameserver einer Domain faelschlicherweise einen "
        "Zone-Transfer (AXFR) an jeden erlaubt -- legt dann die komplette DNS-Zone offen "
        "(alle Subdomains, interne Hostnamen)."
    )
    is_active_scan = False
    timeout_seconds = 25

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
        nameservers_checked: int = 0
        any_vulnerable: bool = False
        results: list[NameserverAxfrResult] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            ns_answer = await asyncio.to_thread(dns.resolver.resolve, data.domain, "NS", lifetime=8)
            nameservers = [str(r.target).rstrip(".") for r in ns_answer]
        except Exception as exc:  # noqa: BLE001
            return self.Output(domain=data.domain, success=False, error=f"Konnte Nameserver nicht ermitteln: {exc}")

        if not nameservers:
            return self.Output(domain=data.domain, success=False, error="Keine Nameserver gefunden")

        nameservers = nameservers[:8]  # Sicherheitsgrenze gegen ungewoehnlich lange NS-Listen
        per_ns_timeout = min(self.timeout_seconds - 8, 6)  # Puffer fuer NS-Aufloesung + Restlaufzeit

        async def check_one(ns_host: str) -> NameserverAxfrResult:
            try:
                ip_answer = await asyncio.to_thread(dns.resolver.resolve, ns_host, "A", lifetime=5)
                ns_ip = str(ip_answer[0])
            except Exception:  # noqa: BLE001
                return NameserverAxfrResult(nameserver=ns_host, ip=None, vulnerable=False, error="IP nicht aufloesbar")

            raw = await asyncio.to_thread(_try_axfr, ns_ip, data.domain, per_ns_timeout)
            return NameserverAxfrResult(nameserver=ns_host, ip=ns_ip, **raw)

        # PARALLEL statt sequenziell pruefen -- bei sequenzieller Pruefung
        # summieren sich die Timeouts (8 Nameserver x 10s waeren 80s
        # gewesen, weit ueber dem eigenen Modul-Timeout). Parallel dauert
        # es nur so lange wie der langsamste einzelne Nameserver.
        results = await asyncio.gather(*(check_one(ns) for ns in nameservers))

        return self.Output(
            domain=data.domain, success=True, nameservers_checked=len(results),
            any_vulnerable=any(r.vulnerable for r in results), results=list(results),
        )

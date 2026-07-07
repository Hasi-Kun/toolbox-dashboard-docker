"""Echte SPF-Auswertung fuer eine konkrete IP -- im Unterschied zum
bestehenden spf-check-Modul (das nur den Record zerlegt/anzeigt) wird
hier tatsaechlich rekursiv ausgewertet, ob eine gegebene IP fuer die
Domain autorisiert waere, inklusive Pass/Fail/Softfail-Ergebnis und
Schritt-fuer-Schritt-Log.
"""

import ipaddress

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip, query
from app.modules.mail.spf import SpfCheckModule

MAX_LOOKUPS = 10
MAX_DEPTH = 10
QUALIFIER_TO_RESULT = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


@register_module
class SpfIpValidatorModule(ToolModule):
    slug = "spf-ip-validator"
    category = "mail"
    name = "SPF IP-Pruefung"
    description = (
        "Prueft, ob eine konkrete IP-Adresse laut dem aktuellen SPF-Record einer Domain zum "
        "Versand berechtigt ist (echte rekursive Auswertung inkl. include/a/mx, nicht nur "
        "Anzeige des Records) -- Ergebnis Pass/Fail/Softfail/Neutral mit Schritt-fuer-Schritt-Log."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        domain_or_email: str
        ip: str

        @field_validator("domain_or_email")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip()
            domain = v.split("@")[-1] if "@" in v else v
            domain = domain.rstrip(".")
            if not is_valid_hostname(domain):
                raise ValueError("Ungueltige Domain oder E-Mail-Adresse")
            return domain

        @field_validator("ip")
        @classmethod
        def validate_ip(cls, v: str) -> str:
            v = v.strip()
            if not is_valid_ip(v):
                raise ValueError("Ungueltige IP-Adresse")
            return v

    class Output(BaseModel):
        domain: str
        ip: str
        result: str
        matched_mechanism: str | None
        trace: list[str]

    async def run(self, data: Input) -> Output:
        trace: list[str] = []
        lookups_used = [0]
        ip_obj = ipaddress.ip_address(data.ip)

        result, matched = await self._evaluate(data.domain_or_email, ip_obj, trace, lookups_used, depth=0)
        return self.Output(domain=data.domain_or_email, ip=data.ip, result=result, matched_mechanism=matched, trace=trace)

    async def _evaluate(
        self, domain: str, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
        trace: list[str], lookups_used: list[int], depth: int,
    ) -> tuple[str, str | None]:
        if depth > MAX_DEPTH or lookups_used[0] > MAX_LOOKUPS:
            trace.append(f"Zu viele verschachtelte Lookups (Limit {MAX_LOOKUPS} laut RFC 7208) -- PermError")
            return "permerror", None

        trace.append(f"Hole SPF-Record fuer '{domain}'")
        dns_result = await query(domain, "TXT", timeout=min(self.timeout_seconds - 3, 8))
        if not dns_result["success"]:
            trace.append(f"Kein TXT-Record erhalten: {dns_result['error']}")
            return "none", None

        spf_records = [r.strip('"') for r in dns_result["records"] if r.strip('"').startswith("v=spf1")]
        if not spf_records:
            trace.append(f"Kein SPF-Record ('v=spf1...') fuer '{domain}' gefunden")
            return "none", None
        if len(spf_records) > 1:
            trace.append(f"{len(spf_records)} SPF-Records gefunden -- laut RFC 7208 ungueltig (PermError)")
            return "permerror", None

        raw = spf_records[0]
        trace.append(f"SPF-Record: {raw}")
        mechanisms = SpfCheckModule._parse(raw)

        for m in mechanisms:
            if m.mechanism in ("ip4", "ip6") and m.value:
                try:
                    network = ipaddress.ip_network(m.value, strict=False)
                except ValueError:
                    trace.append(f"Ungueltiges {m.mechanism}:{m.value} -- uebersprungen")
                    continue
                if ip_obj in network:
                    trace.append(f"Treffer: IP liegt in {m.mechanism}:{m.value} -> Qualifier '{m.qualifier}'")
                    return QUALIFIER_TO_RESULT[m.qualifier], f"{m.mechanism}:{m.value}"
                trace.append(f"Kein Treffer: IP liegt nicht in {m.mechanism}:{m.value}")

            elif m.mechanism == "a":
                lookups_used[0] += 1
                target = m.value or domain
                record_type = "AAAA" if ip_obj.version == 6 else "A"
                trace.append(f"Loese {record_type} fuer '{target}' auf (a-Mechanismus)")
                a_result = await query(target, record_type, timeout=min(self.timeout_seconds - 3, 8))
                if a_result["success"] and str(ip_obj) in a_result["records"]:
                    trace.append(f"Treffer: IP entspricht a:{target} -> Qualifier '{m.qualifier}'")
                    return QUALIFIER_TO_RESULT[m.qualifier], f"a:{target}"
                trace.append(f"Kein Treffer bei a:{target}")

            elif m.mechanism == "mx":
                lookups_used[0] += 1
                target = m.value or domain
                trace.append(f"Loese MX fuer '{target}' auf (mx-Mechanismus)")
                mx_result = await query(target, "MX", timeout=min(self.timeout_seconds - 3, 8))
                if mx_result["success"]:
                    record_type = "AAAA" if ip_obj.version == 6 else "A"
                    for mx_rec in mx_result["records"][:10]:  # RFC-Limit: max 10 MX-Hosts pruefen
                        mx_host = mx_rec.split()[-1].rstrip(".")
                        mx_a = await query(mx_host, record_type, timeout=min(self.timeout_seconds - 3, 8))
                        if mx_a["success"] and str(ip_obj) in mx_a["records"]:
                            trace.append(f"Treffer: IP entspricht MX-Host {mx_host} -> Qualifier '{m.qualifier}'")
                            return QUALIFIER_TO_RESULT[m.qualifier], f"mx:{target}"
                    trace.append(f"Kein Treffer bei mx:{target}")

            elif m.mechanism == "include" and m.value:
                lookups_used[0] += 1
                trace.append(f"Pruefe include:{m.value} (rekursiv)")
                sub_result, sub_matched = await self._evaluate(m.value, ip_obj, trace, lookups_used, depth + 1)
                if sub_result == "pass":
                    trace.append(f"include:{m.value} ergab 'pass' -> uebernommen mit Qualifier '{m.qualifier}'")
                    return QUALIFIER_TO_RESULT[m.qualifier], f"include:{m.value} ({sub_matched})"
                trace.append(f"include:{m.value} ergab '{sub_result}' -- kein Match, naechster Mechanismus")

            elif m.mechanism == "all":
                trace.append(f"Kein spezifischerer Mechanismus hat gegriffen -- 'all' greift -> Qualifier '{m.qualifier}'")
                return QUALIFIER_TO_RESULT[m.qualifier], "all"

        trace.append("Kein Mechanismus hat gegriffen und kein 'all' vorhanden -- Ergebnis neutral")
        return "neutral", None

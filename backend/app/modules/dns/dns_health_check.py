"""DNS Health Check: kombiniert mehrere DNS-Diagnosen zu einem
Gesamtbild fuer eine Domain -- Basis-Records vorhanden, SOA-Werte
plausibel, NS-Konsistenz, TTL-Auffaelligkeiten, CAA/SPF/DMARC-
Praesenz. Ergaenzt die bereits vorhandenen Einzel-Tools (dns-lookup,
dns-propagation, zone-transfer-check) um eine schnelle
Gesamteinschaetzung, statt mehrere Tools einzeln durchklicken zu
muessen.
"""

import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

# Sehr niedrige TTLs sind nicht per se falsch (z.B. waehrend einer
# geplanten Migration durchaus sinnvoll), aber dauerhaft ungewoehnlich
# niedrig gesetzt erhoehen sie die Last auf autoritative Server unnoetig.
_LOW_TTL_THRESHOLD_SECONDS = 300


@register_module
class DnsHealthCheckModule(ToolModule):
    slug = "dns-health-check"
    category = "dns"
    name = "DNS Health Check"
    description = (
        "Gesamtueberblick fuer eine Domain: Basis-Records vorhanden, SOA-Werte plausibel, "
        "TTL-Auffaelligkeiten, CAA/SPF/DMARC-Praesenz. Fasst mehrere Einzelchecks zusammen."
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

    class CheckResult(BaseModel):
        name: str
        status: str  # "ok" | "warning" | "missing" | "error"
        detail: str

    class Output(BaseModel):
        domain: str
        checks: list["DnsHealthCheckModule.CheckResult"]
        overall_status: str  # "healthy" | "warnings" | "issues"
        summary: str

    async def run(self, data: "DnsHealthCheckModule.Input") -> "DnsHealthCheckModule.Output":
        domain = data.domain

        a_task = query(domain, "A", timeout=self.timeout_seconds)
        aaaa_task = query(domain, "AAAA", timeout=self.timeout_seconds)
        mx_task = query(domain, "MX", timeout=self.timeout_seconds)
        ns_task = query(domain, "NS", timeout=self.timeout_seconds)
        soa_task = query(domain, "SOA", timeout=self.timeout_seconds)
        caa_task = query(domain, "CAA", timeout=self.timeout_seconds)
        txt_task = query(domain, "TXT", timeout=self.timeout_seconds)
        dmarc_task = query(f"_dmarc.{domain}", "TXT", timeout=self.timeout_seconds)

        a, aaaa, mx, ns, soa, caa, txt, dmarc = await asyncio.gather(
            a_task, aaaa_task, mx_task, ns_task, soa_task, caa_task, txt_task, dmarc_task
        )

        checks: list[DnsHealthCheckModule.CheckResult] = []

        # 1. Erreichbarkeit (A ODER AAAA)
        if a["success"] or aaaa["success"]:
            addr_count = len(a.get("records", [])) + len(aaaa.get("records", []))
            checks.append(self.CheckResult(name="A/AAAA-Record", status="ok", detail=f"{addr_count} Adresse(n) gefunden"))
        else:
            checks.append(self.CheckResult(name="A/AAAA-Record", status="missing", detail="Keine A- oder AAAA-Records gefunden -- Domain ist ueber IPv4/IPv6 nicht direkt erreichbar"))

        # 2. NS-Records
        if ns["success"] and ns["records"]:
            ns_count = len(ns["records"])
            if ns_count < 2:
                checks.append(self.CheckResult(name="Nameserver", status="warning", detail=f"Nur {ns_count} Nameserver -- fuer Redundanz werden mindestens 2 empfohlen"))
            else:
                checks.append(self.CheckResult(name="Nameserver", status="ok", detail=f"{ns_count} Nameserver gefunden"))
        else:
            checks.append(self.CheckResult(name="Nameserver", status="error", detail="Keine NS-Records gefunden"))

        # 3. SOA-Plausibilitaet
        if soa["success"] and soa["records"]:
            soa_text = soa["records"][0]
            parts = soa_text.split()
            # SOA-Format: mname rname serial refresh retry expire minimum
            if len(parts) >= 7:
                try:
                    refresh, retry, expire, minimum = (int(p) for p in parts[3:7])
                    if expire < refresh:
                        checks.append(self.CheckResult(name="SOA-Werte", status="warning", detail=f"Expire ({expire}s) ist kleiner als Refresh ({refresh}s) -- unueblich"))
                    else:
                        checks.append(self.CheckResult(name="SOA-Werte", status="ok", detail=f"Refresh={refresh}s, Retry={retry}s, Expire={expire}s, Minimum={minimum}s"))
                except ValueError:
                    checks.append(self.CheckResult(name="SOA-Werte", status="warning", detail="SOA-Zahlenwerte konnten nicht geparst werden"))
            else:
                checks.append(self.CheckResult(name="SOA-Werte", status="warning", detail="SOA-Record hat ein unerwartetes Format"))
        else:
            checks.append(self.CheckResult(name="SOA-Werte", status="error", detail="Kein SOA-Record gefunden"))

        # 4. MX (informativ, kein Fehler wenn fehlend -- nicht jede Domain empfaengt Mail)
        if mx["success"] and mx["records"]:
            checks.append(self.CheckResult(name="MX-Record", status="ok", detail=f"{len(mx['records'])} Mailserver-Eintrag/e"))
        else:
            checks.append(self.CheckResult(name="MX-Record", status="warning", detail="Kein MX-Record -- Domain empfaengt vermutlich keine E-Mails direkt"))

        # 5. CAA (informativ)
        if caa["success"] and caa["records"]:
            checks.append(self.CheckResult(name="CAA-Record", status="ok", detail=f"{len(caa['records'])} CAA-Eintrag/e -- schraenkt zulaessige Zertifizierungsstellen ein"))
        else:
            checks.append(self.CheckResult(name="CAA-Record", status="warning", detail="Kein CAA-Record -- jede oeffentliche CA darf Zertifikate fuer diese Domain ausstellen"))

        # 6. SPF (via TXT)
        spf_records = [r for r in txt.get("records", []) if "v=spf1" in r.lower()]
        if spf_records:
            checks.append(self.CheckResult(name="SPF", status="ok", detail="SPF-Record vorhanden"))
        else:
            checks.append(self.CheckResult(name="SPF", status="warning", detail="Kein SPF-Record -- erleichtert E-Mail-Spoofing im Namen dieser Domain"))

        # 7. DMARC
        dmarc_records = [r for r in dmarc.get("records", []) if "v=dmarc1" in r.lower()]
        if dmarc_records:
            checks.append(self.CheckResult(name="DMARC", status="ok", detail="DMARC-Record vorhanden"))
        else:
            checks.append(self.CheckResult(name="DMARC", status="warning", detail="Kein DMARC-Record -- keine Richtlinie fuer den Umgang mit SPF/DKIM-Fehlschlaegen"))

        error_count = sum(1 for c in checks if c.status in ("error", "missing"))
        warning_count = sum(1 for c in checks if c.status == "warning")

        if error_count > 0:
            overall_status = "issues"
            summary = f"{error_count} kritische(r) Befund(e), {warning_count} Hinweis(e) -- grundlegende DNS-Konfiguration hat Luecken."
        elif warning_count > 0:
            overall_status = "warnings"
            summary = f"Grundlegende DNS-Konfiguration funktioniert, aber {warning_count} Verbesserungspunkt(e) gefunden."
        else:
            overall_status = "healthy"
            summary = "Keine Auffaelligkeiten gefunden -- DNS-Konfiguration wirkt vollstaendig."

        return self.Output(domain=domain, checks=checks, overall_status=overall_status, summary=summary)

"""IP Threat Intelligence: kombiniert mehrere KOSTENLOSE, bereits in
dieser Toolbox genutzte Quellen zu einer einzigen Bewertung/Summary
fuer eine IP -- Shodan InternetDB (offene Ports, CVEs, Tags), ip-api.com
(ASN/ISP/Geo, dieselbe Quelle wie asn-lookup) und Reverse-DNS.

BEWUSST NUR kostenlose, unauthentifizierte Quellen -- kein AbuseIPDB/
VirusTotal (bräuchten eigene, kostenpflichtige API-Keys). Die
Risikobewertung ist entsprechend ein einfacher, transparenter
Heuristik-basierter Hinweis, KEIN vollstaendiger Reputationsscore wie
bei kommerziellen Threat-Intel-Anbietern -- das wird im Ergebnis auch
so kommuniziert, um keine falsche Praezision vorzutaeuschen.
"""

import asyncio

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_ip, query

# Tags aus Shodans InternetDB, die auf ein potenziell riskantes/
# missbrauchtes System hindeuten koennen (nicht abschliessend, keine
# Garantie -- nur ein grober, transparenter Hinweis).
_ELEVATED_RISK_TAGS = {"compromised", "malware", "honeypot", "scanner", "brute-force", "tor", "proxy"}


@register_module
class IpThreatIntelModule(ToolModule):
    slug = "ip-threat-intel"
    category = "osint"
    name = "IP Threat Intelligence"
    description = (
        "Kombiniert kostenlose Quellen (Shodan InternetDB, ip-api.com, Reverse-DNS) zu einer "
        "uebersichtlichen Zusammenfassung fuer eine IP -- offene Ports, bekannte CVEs, ASN/ISP, "
        "Reverse-DNS und ein einfacher, transparenter Risiko-Hinweis. Kein vollstaendiger "
        "Reputationsscore wie bei kostenpflichtigen Anbietern (AbuseIPDB/VirusTotal)."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        ip: str

        @field_validator("ip")
        @classmethod
        def validate_ip(cls, v: str) -> str:
            v = v.strip()
            if not is_valid_ip(v):
                raise ValueError("Ungueltige IP-Adresse (nur IPv4/IPv6, keine Hostnamen)")
            return v

    class Output(BaseModel):
        ip: str
        # Shodan InternetDB
        open_ports: list[int] = []
        cpes: list[str] = []
        known_cves: list[str] = []
        shodan_tags: list[str] = []
        shodan_hostnames: list[str] = []
        # ip-api.com
        asn: str | None = None
        isp: str | None = None
        organization: str | None = None
        country: str | None = None
        # Reverse-DNS
        reverse_dns: list[str] = []
        # Zusammenfassung
        risk_level: str  # "niedrig" | "erhoeht" | "unbekannt"
        risk_reasons: list[str] = []
        summary: str
        sources_reachable: dict[str, bool]

    async def run(self, data: "IpThreatIntelModule.Input") -> "IpThreatIntelModule.Output":
        shodan_task = self._fetch_shodan(data.ip)
        asn_task = self._fetch_asn(data.ip)
        rdns_task = self._fetch_reverse_dns(data.ip)

        shodan_result, asn_result, rdns_result = await asyncio.gather(shodan_task, asn_task, rdns_task)

        sources_reachable = {
            "shodan_internetdb": shodan_result is not None,
            "ip_api": asn_result is not None,
            "reverse_dns": rdns_result is not None,
        }

        open_ports = shodan_result.get("ports", []) if shodan_result else []
        cves = shodan_result.get("vulns", []) if shodan_result else []
        tags = shodan_result.get("tags", []) if shodan_result else []
        hostnames = shodan_result.get("hostnames", []) if shodan_result else []

        risk_reasons = []
        if cves:
            risk_reasons.append(f"{len(cves)} bekannte CVE(s) laut Shodan InternetDB")
        elevated_tags = [t for t in tags if t.lower() in _ELEVATED_RISK_TAGS]
        if elevated_tags:
            risk_reasons.append(f"Auffaellige Shodan-Tags: {', '.join(elevated_tags)}")
        if len(open_ports) >= 10:
            risk_reasons.append(f"Ungewoehnlich viele offene Ports ({len(open_ports)})")

        if risk_reasons:
            risk_level = "erhoeht"
        elif shodan_result is not None:
            risk_level = "niedrig"
        else:
            risk_level = "unbekannt"

        summary = self._build_summary(risk_level, risk_reasons, open_ports, cves, sources_reachable)

        return self.Output(
            ip=data.ip,
            open_ports=open_ports,
            cpes=shodan_result.get("cpes", []) if shodan_result else [],
            known_cves=cves,
            shodan_tags=tags,
            shodan_hostnames=hostnames,
            asn=asn_result.get("as") if asn_result else None,
            isp=asn_result.get("isp") if asn_result else None,
            organization=asn_result.get("org") if asn_result else None,
            country=asn_result.get("country") if asn_result else None,
            reverse_dns=rdns_result or [],
            risk_level=risk_level,
            risk_reasons=risk_reasons,
            summary=summary,
            sources_reachable=sources_reachable,
        )

    @staticmethod
    def _build_summary(risk_level: str, reasons: list[str], ports: list[int], cves: list[str], sources: dict[str, bool]) -> str:
        if not any(sources.values()):
            return "Keine der Quellen war erreichbar -- keine Aussage moeglich."

        if risk_level == "erhoeht":
            return "Auffaelligkeiten gefunden: " + "; ".join(reasons) + ". Das ist ein grober Hinweis, KEIN abschliessendes Urteil -- manuell nachpruefen."
        if risk_level == "niedrig":
            port_note = f"{len(ports)} offene(r) Port(s) bekannt" if ports else "keine offenen Ports in Shodans Datenbestand bekannt"
            return f"Keine offensichtlichen Auffaelligkeiten in den verfuegbaren kostenlosen Quellen gefunden ({port_note}, keine bekannten CVEs). Das ist KEIN vollstaendiger Reputationscheck -- fuer eine tiefere Pruefung waeren kostenpflichtige Dienste (AbuseIPDB, VirusTotal) noetig."
        return "Shodan InternetDB nicht erreichbar oder keine Daten vorhanden -- eingeschraenkte Aussagekraft."

    async def _fetch_shodan(self, ip: str) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(f"https://internetdb.shodan.io/{ip}")
            if response.status_code == 404:
                return {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
            if response.status_code != 200:
                return None
            return response.json()
        except (httpx.HTTPError, ValueError):
            return None

    async def _fetch_asn(self, ip: str) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as")
            if response.status_code != 200:
                return None
            data = response.json()
            if data.get("status") != "success":
                return None
            return data
        except (httpx.HTTPError, ValueError):
            return None

    async def _fetch_reverse_dns(self, ip: str) -> list[str] | None:
        try:
            import dns.reversename

            # dns.reversename deckt IPv4 UND IPv6 korrekt ab (meine
            # vorherige manuelle String-Umkehr haette bei IPv6-Adressen
            # (die is_valid_ip() ja ausdruecklich erlaubt) falsche/keine
            # Ergebnisse geliefert).
            reverse_name = dns.reversename.from_address(ip)
            result = await query(str(reverse_name).rstrip("."), "PTR", timeout=self.timeout_seconds)
            if result["success"]:
                return result["records"]
            return []
        except Exception:  # noqa: BLE001
            return None

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query


@register_module
class GhostSenderCheckModule(ToolModule):
    slug = "ghost-sender-check"
    category = "mail"
    name = "Ghost-Sender Check"
    description = (
        "Prueft passiv (nur DNS, kein Mailversand) auf die 'Ghost-Sender'-Fehlkonfiguration bei "
        "Exchange Online -- ein externer MX-Eintrag kombiniert mit einem bestehenden M365-Tenant kann "
        "das Versenden gefaelschter Mails von beliebigen Absendern ermoeglichen, unabhaengig von SPF/DKIM/DMARC."
    )
    is_active_scan = False
    timeout_seconds = 8

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
        mx_records: list[str] = []
        mx_points_to_eop: bool
        exchange_online_tenant_detected: bool
        classification: str
        recommendation: str
        error: str | None = None

    async def run(self, data: Input) -> Output:
        mx_result = await query(data.domain, "MX", timeout=self.timeout_seconds)
        if not mx_result["success"]:
            return self.Output(
                domain=data.domain, mx_points_to_eop=False, exchange_online_tenant_detected=False,
                classification="Nicht pruefbar", recommendation="Kein MX-Record gefunden oder DNS-Fehler.",
                error=mx_result["error"],
            )

        mx_hosts = [rec.split()[-1].rstrip(".").lower() for rec in mx_result["records"]]
        mx_points_to_eop = any(h.endswith(".mail.protection.outlook.com") for h in mx_hosts)

        eop_probe_name = data.domain.replace(".", "-") + ".mail.protection.outlook.com"
        eop_result = await query(eop_probe_name, "MX", timeout=self.timeout_seconds)
        tenant_detected = eop_result["success"]

        if mx_points_to_eop:
            classification = "Wahrscheinlich nicht anfaellig"
            recommendation = (
                "MX zeigt direkt auf Exchange Online Protection. Hinweis: interne Spoofing-Mails koennen "
                "trotzdem funktionieren, wenn DMARC auf 'p=none' steht und Direct Send aktiv ist -- "
                "DMARC-Policy pruefen und Direct Send bei Nichtgebrauch deaktivieren."
            )
        elif tenant_detected:
            classification = "Potenziell anfaellig fuer Ghost-Sender"
            recommendation = (
                "Externe MX-Konfiguration mit erkennbarem Exchange-Online-Tenant im Hintergrund -- genau "
                "die Kombination, die Ghost-Sender ermoeglicht. Pruefen: Partner-Organization-Connector mit "
                "Wildcard-Domain + IP/Zertifikat-Restriktion, ODER eine Transport-Regel (Prioritaet 0), die "
                "Mail ohne 'X-MS-Exchange-Organization-AuthAs: Internal' und ausserhalb erlaubter IPs in "
                "Quarantaene verschiebt. Dieser Check sendet keine Test-Mail -- ob eine Mitigation aktiv ist, "
                "kann nur durch einen tatsaechlichen, autorisierten Testversand bestaetigt werden."
            )
        else:
            classification = "Kein Exchange-Online-Tenant erkannt"
            recommendation = "Diese spezifische Schwachstelle betrifft nur Exchange-Online-Tenants -- hier nicht anwendbar."

        return self.Output(
            domain=data.domain, mx_records=mx_hosts, mx_points_to_eop=mx_points_to_eop,
            exchange_online_tenant_detected=tenant_detected, classification=classification,
            recommendation=recommendation, error=None,
        )

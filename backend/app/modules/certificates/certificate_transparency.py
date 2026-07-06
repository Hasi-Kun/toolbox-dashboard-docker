import asyncio
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname

MAX_DETAILED_ENTRIES = 30
MAX_ATTEMPTS = 3
PER_ATTEMPT_TIMEOUT = 10.0
RETRY_DELAY_SECONDS = 1.5
# Status-Codes, die auf ein VORUEBERGEHENDES crt.sh-Problem hindeuten
# (eigener Server ueberlastet) -- dafuer lohnt sich ein Retry. Ein 4xx
# (z.B. ungueltige Anfrage) wuerde beim Wiederholen nicht anders ausgehen.
_RETRYABLE_STATUS_CODES = {502, 503, 504}


class CertificateEntry(BaseModel):
    id: int | None = None
    common_name: str | None = None
    subject_alternative_names: list[str] = []
    issuer_name: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    is_expired: bool | None = None


@register_module
class CertificateTransparencyModule(ToolModule):
    slug = "certificate-transparency"
    category = "certificates"
    name = "Certificate Transparency"
    description = (
        "Durchsucht oeffentliche CT-Logs (ueber crt.sh) nach allen jemals ausgestellten "
        "Zertifikaten fuer eine Domain -- findet oft vergessene Subdomains. Zeigt fuer die "
        f"letzten {MAX_DETAILED_ENTRIES} Zertifikate Details (Ausstellungsdatum, Ablaufdatum, "
        "CA, Seriennummer, SANs)."
    )
    is_active_scan = False
    timeout_seconds = 35  # crt.sh ist bei grossen Domains bekanntermassen langsam

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
        total_certificates: int
        unique_subdomains: list[str] = []
        issuers: list[str] = []
        recent_certificates: list[CertificateEntry] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = f"https://crt.sh/?q=%25.{data.domain}&output=json"
        response = None
        last_error: str | None = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=PER_ATTEMPT_TIMEOUT) as client:
                    response = await client.get(url, headers={"User-Agent": "Toolbox-CT-Lookup/1.0"})
            except httpx.HTTPError as exc:
                last_error = str(exc)
                response = None
            else:
                if response.status_code == 200:
                    break
                last_error = f"crt.sh antwortete mit HTTP {response.status_code}"
                if response.status_code not in _RETRYABLE_STATUS_CODES:
                    break  # kein voruebergehendes Problem -- Wiederholen wuerde nichts aendern

            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(RETRY_DELAY_SECONDS)

        if response is None or response.status_code != 200:
            return self.Output(
                domain=data.domain, success=False, total_certificates=0,
                error=f"{last_error} (crt.sh ist ein unbezahlter Community-Dienst und gelegentlich "
                f"ueberlastet -- nach {MAX_ATTEMPTS} Versuchen aufgegeben, spaeter nochmal probieren)",
            )

        try:
            entries = response.json()
        except ValueError:
            return self.Output(
                domain=data.domain, success=False, total_certificates=0,
                error="crt.sh-Antwort konnte nicht als JSON gelesen werden (evtl. Rate-Limit)",
            )

        subdomains: set[str] = set()
        issuers: set[str] = set()

        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name:
                    subdomains.add(name)
            issuer = entry.get("issuer_name")
            if issuer:
                issuers.add(issuer)

        # Neueste zuerst, auf eine sinnvolle Menge begrenzt (manche Domains
        # haben tausende Eintraege -- niemand braucht die alle im Detail).
        sorted_entries = sorted(entries, key=lambda e: e.get("not_before") or "", reverse=True)
        recent: list[CertificateEntry] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for entry in sorted_entries[:MAX_DETAILED_ENTRIES]:
            not_after = entry.get("not_after")
            sans = sorted({n.strip().lower() for n in entry.get("name_value", "").split("\n") if n.strip()})
            recent.append(
                CertificateEntry(
                    id=entry.get("id"),
                    common_name=entry.get("common_name"),
                    subject_alternative_names=sans,
                    issuer_name=entry.get("issuer_name"),
                    serial_number=entry.get("serial_number"),
                    not_before=entry.get("not_before"),
                    not_after=not_after,
                    is_expired=(not_after < now_iso) if not_after else None,
                )
            )

        return self.Output(
            domain=data.domain,
            success=True,
            total_certificates=len(entries),
            unique_subdomains=sorted(subdomains),
            issuers=sorted(issuers),
            recent_certificates=recent,
            error=None,
        )

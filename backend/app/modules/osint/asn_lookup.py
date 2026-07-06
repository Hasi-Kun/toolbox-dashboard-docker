import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip


@register_module
class AsnLookupModule(ToolModule):
    slug = "asn-lookup"
    category = "osint"
    name = "ASN Lookup"
    description = (
        "Ermittelt das Autonome System (ASN), den Netzbetreiber und die Organisation hinter "
        "einer IP/Domain -- nuetzlich um Infrastruktur/Hosting-Zusammenhaenge zu erkennen."
    )
    is_active_scan = False
    timeout_seconds = 8

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
        success: bool
        ip: str | None = None
        asn: str | None = None
        as_name: str | None = None
        isp: str | None = None
        organization: str | None = None
        country: str | None = None
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = f"http://ip-api.com/json/{data.target}?fields=status,message,query,country,isp,org,as"

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return self.Output(target=data.target, success=False, error=str(exc))

        if payload.get("status") != "success":
            return self.Output(target=data.target, success=False, error=payload.get("message", "Lookup fehlgeschlagen"))

        as_field = payload.get("as", "")
        asn, _, as_name = as_field.partition(" ")

        return self.Output(
            target=data.target, success=True, ip=payload.get("query"),
            asn=asn or None, as_name=as_name or None,
            isp=payload.get("isp"), organization=payload.get("org"),
            country=payload.get("country"), error=None,
        )

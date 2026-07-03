import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname


@register_module
class CertificateTransparencyModule(ToolModule):
    slug = "certificate-transparency"
    category = "certificates"
    name = "Certificate Transparency"
    description = (
        "Durchsucht oeffentliche CT-Logs (ueber crt.sh) nach allen jemals ausgestellten "
        "Zertifikaten fuer eine Domain -- findet oft vergessene Subdomains."
    )
    is_active_scan = False
    timeout_seconds = 15

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
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = f"https://crt.sh/?q=%25.{data.domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url, headers={"User-Agent": "Toolbox-CT-Lookup/1.0"})
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, total_certificates=0, error=str(exc))

        if response.status_code != 200:
            return self.Output(
                domain=data.domain, success=False, total_certificates=0,
                error=f"crt.sh antwortete mit HTTP {response.status_code}",
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

        return self.Output(
            domain=data.domain,
            success=True,
            total_certificates=len(entries),
            unique_subdomains=sorted(subdomains),
            issuers=sorted(issuers),
            error=None,
        )

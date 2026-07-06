from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

_USAGE_LABELS = {
    "0": "PKIX-TA (CA constraint)",
    "1": "PKIX-EE (service certificate constraint)",
    "2": "DANE-TA (trust anchor assertion)",
    "3": "DANE-EE (domain issued certificate)",
}
_SELECTOR_LABELS = {"0": "Vollzertifikat", "1": "Public Key"}
_MATCHING_LABELS = {"0": "Exact match", "1": "SHA-256", "2": "SHA-512"}


class TlsaRecord(BaseModel):
    raw: str
    certificate_usage: str
    selector: str
    matching_type: str


@register_module
class DaneCheckModule(ToolModule):
    slug = "dane-check"
    category = "mail"
    name = "DANE Check"
    description = "Prueft TLSA-Records (DNS-based Authentication of Named Entities) fuer einen Mailserver."
    is_active_scan = False
    timeout_seconds = 8

    class Input(BaseModel):
        domain: str
        port: int = 25

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            if not (1 <= v <= 65535):
                raise ValueError("Ungueltiger Port")
            return v

    class Output(BaseModel):
        domain: str
        port: int
        found: bool
        records: list[TlsaRecord] = []
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        query_name = f"_{data.port}._tcp.{data.domain}"
        result = await query(query_name, "TLSA", timeout=self.timeout_seconds)

        if not result["success"]:
            return self.Output(
                domain=data.domain, port=data.port, found=False,
                warnings=["Kein TLSA-Record gefunden -- DANE ist fuer diesen Mailserver nicht aktiv."],
                error=None,
            )

        records: list[TlsaRecord] = []
        for raw in result["records"]:
            parts = raw.split()
            if len(parts) >= 3:
                usage, selector, matching = parts[0], parts[1], parts[2]
                records.append(TlsaRecord(raw=raw, certificate_usage=_USAGE_LABELS.get(usage, usage), selector=_SELECTOR_LABELS.get(selector, selector), matching_type=_MATCHING_LABELS.get(matching, matching)))

        return self.Output(domain=data.domain, port=data.port, found=True, records=records, error=None)

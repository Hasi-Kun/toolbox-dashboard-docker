from typing import Literal

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

RecordType = Literal["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA"]


@register_module
class DnsLookupModule(ToolModule):
    slug = "dns-lookup"
    category = "dns"
    name = "DNS Lookup"
    description = "Loest DNS-Records (A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA) fuer eine Domain auf."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        domain: str
        record_type: RecordType = "A"

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltiger Hostname")
            return v

    class Output(BaseModel):
        domain: str
        record_type: str
        success: bool
        records: list[str]
        ttl: int | None
        error: str | None

    async def run(self, data: Input) -> Output:
        result = await query(data.domain, data.record_type, timeout=self.timeout_seconds)
        return self.Output(domain=data.domain, record_type=data.record_type, **result)

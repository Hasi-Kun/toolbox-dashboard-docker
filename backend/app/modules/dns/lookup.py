import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip, query

# Deutlich erweiterte Liste gegenueber der urspruenglichen 9 Typen --
# orientiert an digwebinterface.com, das viele Record-Typen gleichzeitig
# abfragen laesst statt nur einen pro Anfrage.
ALL_RECORD_TYPES = [
    "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA",
    "PTR", "DNSKEY", "DS", "NAPTR", "TLSA", "HINFO", "RP", "LOC", "SSHFP", "NSEC",
]
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS"]


class RecordTypeResult(BaseModel):
    record_type: str
    success: bool
    records: list[str] = []
    ttl: int | None = None
    error: str | None = None


@register_module
class DnsLookupModule(ToolModule):
    slug = "dns-lookup"
    category = "dns"
    name = "DNS Lookup"
    description = (
        f"Loest mehrere DNS-Record-Typen gleichzeitig auf ({', '.join(ALL_RECORD_TYPES)}), optional "
        "gegen einen bestimmten Nameserver -- aehnlich wie digwebinterface.com."
    )
    is_active_scan = False
    timeout_seconds = 12

    class Input(BaseModel):
        domain: str
        record_types: list[str] = DEFAULT_RECORD_TYPES
        custom_nameserver: str | None = None

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltiger Hostname")
            return v

        @field_validator("record_types")
        @classmethod
        def validate_record_types(cls, v: list[str]) -> list[str]:
            v = [t.strip().upper() for t in v if t.strip()]
            if not v:
                raise ValueError("Mindestens ein Record-Typ noetig")
            unknown = set(v) - set(ALL_RECORD_TYPES)
            if unknown:
                raise ValueError(f"Unbekannte Record-Typen: {sorted(unknown)}")
            if len(v) > len(ALL_RECORD_TYPES):
                raise ValueError("Zu viele Record-Typen")
            return v

        @field_validator("custom_nameserver")
        @classmethod
        def validate_nameserver(cls, v: str | None) -> str | None:
            if v is None or not v.strip():
                return None
            v = v.strip()
            if not is_valid_ip(v):
                raise ValueError("Custom-Nameserver muss eine gueltige IP-Adresse sein")
            return v

    class Output(BaseModel):
        domain: str
        nameserver_used: str | None
        results: list[RecordTypeResult]

    async def run(self, data: Input) -> Output:
        async def lookup(record_type: str) -> RecordTypeResult:
            result = await query(
                data.domain, record_type, nameserver=data.custom_nameserver,
                timeout=min(self.timeout_seconds - 2, 8),
            )
            return RecordTypeResult(record_type=record_type, **result)

        results = await asyncio.gather(*(lookup(rt) for rt in data.record_types))
        return self.Output(domain=data.domain, nameserver_used=data.custom_nameserver, results=list(results))

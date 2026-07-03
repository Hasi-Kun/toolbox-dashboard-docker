import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import PUBLIC_RESOLVERS, is_valid_hostname, query


class ResolverResult(BaseModel):
    resolver: str
    nameserver: str
    success: bool
    records: list[str]
    error: str | None


@register_module
class DnsPropagationModule(ToolModule):
    slug = "dns-propagation"
    category = "dns"
    name = "DNS Propagation Check"
    description = f"Vergleicht DNS-Antworten von {len(PUBLIC_RESOLVERS)} globalen Resolvern."
    is_active_scan = False
    timeout_seconds = 6

    class Input(BaseModel):
        domain: str
        record_type: str = "A"

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
        results: list[ResolverResult]
        fully_propagated: bool

    async def run(self, data: Input) -> Output:
        tasks = [
            self._query_one(name, ip, data.domain, data.record_type)
            for name, ip in PUBLIC_RESOLVERS.items()
        ]
        results: list[ResolverResult] = await asyncio.gather(*tasks)

        successful_sets = {frozenset(r.records) for r in results if r.success}
        fully_propagated = len(successful_sets) <= 1 and all(r.success for r in results)

        return self.Output(
            domain=data.domain,
            record_type=data.record_type,
            results=results,
            fully_propagated=fully_propagated,
        )

    async def _query_one(self, name: str, ip: str, domain: str, record_type: str) -> ResolverResult:
        result = await query(domain, record_type, nameserver=ip, timeout=self.timeout_seconds)
        return ResolverResult(resolver=name, nameserver=ip, **result)

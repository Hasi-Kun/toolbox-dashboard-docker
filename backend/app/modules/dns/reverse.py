import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_ip


@register_module
class DnsReverseLookupModule(ToolModule):
    slug = "dns-reverse-lookup"
    category = "dns"
    name = "Reverse Lookup (PTR)"
    description = "Ermittelt den Hostnamen zu einer IP-Adresse."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        ip: str

        @field_validator("ip")
        @classmethod
        def validate_ip(cls, v: str) -> str:
            v = v.strip()
            if not is_valid_ip(v):
                raise ValueError("Ungueltige IP-Adresse")
            return v

    class Output(BaseModel):
        ip: str
        success: bool
        hostnames: list[str]
        error: str | None

    async def run(self, data: Input) -> Output:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout_seconds
        resolver.lifetime = self.timeout_seconds

        try:
            rev_name = dns.reversename.from_address(data.ip)
            answer = await resolver.resolve(rev_name, "PTR")
            hostnames = [rdata.to_text().rstrip(".") for rdata in answer]
            return self.Output(ip=data.ip, success=True, hostnames=hostnames, error=None)
        except dns.resolver.NXDOMAIN:
            return self.Output(ip=data.ip, success=False, hostnames=[], error="Kein PTR-Record vorhanden")
        except dns.exception.Timeout:
            return self.Output(ip=data.ip, success=False, hostnames=[], error="Zeitueberschreitung bei der Anfrage")
        except Exception as exc:  # noqa: BLE001
            return self.Output(ip=data.ip, success=False, hostnames=[], error=str(exc))

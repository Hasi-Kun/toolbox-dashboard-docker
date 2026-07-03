import ipaddress

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module


@register_module
class CidrCalculatorModule(ToolModule):
    slug = "cidr-calculator"
    category = "utilities"
    name = "CIDR Rechner"
    description = "Berechnet Netzwerk-/Broadcast-Adresse, Subnetzmaske und nutzbaren Adressbereich fuer ein CIDR."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        cidr: str

        @field_validator("cidr")
        @classmethod
        def validate_cidr(cls, v: str) -> str:
            v = v.strip()
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError as exc:
                raise ValueError(f"Ungueltiges CIDR: {exc}") from exc
            return v

    class Output(BaseModel):
        cidr: str
        version: int
        network_address: str
        broadcast_address: str | None
        netmask: str
        wildcard_mask: str | None
        prefix_length: int
        total_addresses: int
        usable_addresses: int
        first_usable: str | None
        last_usable: str | None
        is_private: bool

    async def run(self, data: Input) -> Output:
        network = ipaddress.ip_network(data.cidr, strict=False)
        hosts = list(network.hosts())

        return self.Output(
            cidr=str(network),
            version=network.version,
            network_address=str(network.network_address),
            broadcast_address=str(network.broadcast_address) if network.version == 4 else None,
            netmask=str(network.netmask),
            wildcard_mask=str(ipaddress.IPv4Address(int(network.hostmask))) if network.version == 4 else None,
            prefix_length=network.prefixlen,
            total_addresses=network.num_addresses,
            usable_addresses=len(hosts),
            first_usable=str(hosts[0]) if hosts else None,
            last_usable=str(hosts[-1]) if hosts else None,
            is_private=network.is_private,
        )

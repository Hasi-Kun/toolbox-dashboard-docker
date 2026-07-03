import asyncio

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

MAX_PORTS = 10


class PortResult(BaseModel):
    port: int
    status: str  # "open" | "closed" | "filtered"


@register_module
class PortCheckModule(ToolModule):
    slug = "port-check"
    category = "network"
    name = "Port Check"
    description = (
        f"Prueft bis zu {MAX_PORTS} explizit angegebene Ports per TCP-Connect. "
        "Kein Scanner -- fuer breites Port-Scanning siehe Nmap-Kategorie (Phase 5)."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        host: str
        ports: list[int]

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiger Host (Hostname oder IP erwartet)")
            return v

        @field_validator("ports")
        @classmethod
        def validate_ports(cls, v: list[int]) -> list[int]:
            if not v:
                raise ValueError("Mindestens ein Port erforderlich")
            if len(v) > MAX_PORTS:
                raise ValueError(f"Maximal {MAX_PORTS} Ports pro Anfrage (kein Scanner)")
            for port in v:
                if not (1 <= port <= 65535):
                    raise ValueError(f"Ungueltiger Port: {port}")
            return v

    class Output(BaseModel):
        host: str
        results: list[PortResult]

    async def run(self, data: Input) -> Output:
        results = await asyncio.gather(*(self._check_port(data.host, port) for port in data.ports))
        return self.Output(host=data.host, results=list(results))

    @staticmethod
    async def _check_port(host: str, port: int) -> PortResult:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001 -- Verbindung ist eh schon zu, egal wie das genau ausgeht
                pass
            return PortResult(port=port, status="open")
        except asyncio.TimeoutError:
            return PortResult(port=port, status="filtered")
        except (ConnectionRefusedError, OSError):
            return PortResult(port=port, status="closed")

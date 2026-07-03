import re

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip
from app.modules.network.common import run_subprocess

# z.B. " 3  203.0.113.1 (203.0.113.1)  12.345 ms"
_HOP_RE = re.compile(r"^\s*(\d+)\s+(.+?)\s+([\d.]+)\s*ms", re.MULTILINE)


class TracerouteHop(BaseModel):
    hop: int
    host: str
    rtt_ms: float | None


@register_module
class TracerouteModule(ToolModule):
    slug = "traceroute"
    category = "network"
    name = "Traceroute"
    description = "Zeigt den Netzwerkpfad zu einem Host, Hop fuer Hop."
    is_active_scan = False
    timeout_seconds = 35

    class Input(BaseModel):
        host: str
        max_hops: int = 20

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiger Host (Hostname oder IP erwartet)")
            return v

        @field_validator("max_hops")
        @classmethod
        def validate_max_hops(cls, v: int) -> int:
            return max(1, min(v, 30))

    class Output(BaseModel):
        host: str
        success: bool
        hops: list[TracerouteHop]
        raw_output: str
        error: str | None

    async def run(self, data: Input) -> Output:
        result = await run_subprocess(
            ["traceroute", "-m", str(data.max_hops), "-w", "1", "-q", "1", data.host],
            timeout=self.timeout_seconds,
        )

        if result["error"]:
            return self.Output(host=data.host, success=False, hops=[], raw_output="", error=result["error"])

        hops = [
            TracerouteHop(hop=int(m.group(1)), host=m.group(2).strip(), rtt_ms=float(m.group(3)))
            for m in _HOP_RE.finditer(result["stdout"])
        ]

        return self.Output(
            host=data.host,
            success=result["success"],
            hops=hops,
            raw_output=result["stdout"],
            error=None if result["success"] else "Traceroute fehlgeschlagen",
        )

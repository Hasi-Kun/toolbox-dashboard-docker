import re

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip
from app.modules.network.common import run_subprocess

# z.B. "4 packets transmitted, 4 received, 0% packet loss, time 3005ms"
_STATS_RE = re.compile(r"(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss")
# z.B. "rtt min/avg/max/mdev = 12.345/13.456/14.567/0.789 ms"
_RTT_RE = re.compile(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")


@register_module
class PingModule(ToolModule):
    slug = "ping"
    category = "network"
    name = "Ping"
    description = "Sendet ICMP Echo Requests und misst Antwortzeit/Paketverlust."
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        host: str
        count: int = 4

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiger Host (Hostname oder IP erwartet)")
            return v

        @field_validator("count")
        @classmethod
        def validate_count(cls, v: int) -> int:
            return max(1, min(v, 10))

    class Output(BaseModel):
        host: str
        success: bool
        packets_sent: int | None
        packets_received: int | None
        packet_loss_percent: float | None
        rtt_min_ms: float | None
        rtt_avg_ms: float | None
        rtt_max_ms: float | None
        raw_output: str
        error: str | None

    async def run(self, data: Input) -> Output:
        result = await run_subprocess(
            ["ping", "-c", str(data.count), "-W", "2", data.host], timeout=self.timeout_seconds
        )

        if result["error"]:
            return self.Output(
                host=data.host, success=False, packets_sent=None, packets_received=None,
                packet_loss_percent=None, rtt_min_ms=None, rtt_avg_ms=None, rtt_max_ms=None,
                raw_output="", error=result["error"],
            )

        output = result["stdout"]
        stats_match = _STATS_RE.search(output)
        rtt_match = _RTT_RE.search(output)

        return self.Output(
            host=data.host,
            success=result["success"],
            packets_sent=int(stats_match.group(1)) if stats_match else None,
            packets_received=int(stats_match.group(2)) if stats_match else None,
            packet_loss_percent=float(stats_match.group(3)) if stats_match else None,
            rtt_min_ms=float(rtt_match.group(1)) if rtt_match else None,
            rtt_avg_ms=float(rtt_match.group(2)) if rtt_match else None,
            rtt_max_ms=float(rtt_match.group(3)) if rtt_match else None,
            raw_output=output,
            error=None if result["success"] else "Host nicht erreichbar",
        )

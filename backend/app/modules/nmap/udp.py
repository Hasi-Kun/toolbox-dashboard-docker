from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.nmap.common import NmapHost, validate_scan_target

MAX_UDP_PORTS = 50  # UDP-Scans sind deutlich langsamer als TCP -- bewusst enger begrenzt


@register_module
class NmapUdpScanModule(ToolModule):
    slug = "nmap-udp"
    category = "nmap"
    name = "UDP Scan"
    description = f"Scannt die haeufigsten UDP-Ports (max. {MAX_UDP_PORTS}, nmap -sU). Deutlich langsamer als TCP."
    is_active_scan = True
    # timeout_seconds steuert NUR noch den alten synchronen Fallback-Pfad
    # (run()) fuer direkte API-Aufrufer, die nicht das neue Polling-Muster
    # (scan/start + scan/status) nutzen -- bewusst bei 5 Minuten gedeckelt,
    # damit ein synchroner Aufruf nicht wieder eine einzelne, lange offene
    # HTTP-Verbindung braucht (das war die urspruengliche Cloudflare/
    # Reverse-Proxy-Timeout-Problematik). Die tatsaechliche Obergrenze fuer
    # lange Scans (bis zu 30 Minuten) liegt jetzt beim Scanner-Container
    # selbst (SUBPROCESS_TIMEOUT_BY_TEMPLATE in scanner/app/worker.py) --
    # das Polling-Frontend wartet dort entsprechend laenger.
    timeout_seconds = 300
    scan_template = "udp"

    class Input(BaseModel):
        target: str
        count: int = 20

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            return validate_scan_target(v)

        @field_validator("count")
        @classmethod
        def validate_count(cls, v: int) -> int:
            return max(1, min(v, MAX_UDP_PORTS))

    class Output(BaseModel):
        target: str
        success: bool
        hosts: list[NmapHost] = []
        error: str | None = None

    def build_scan_params(self, data: Input) -> dict:
        return {"target": data.target, "count": data.count}

    def parse_scan_result(self, data: Input, raw: dict) -> Output:
        if raw.get("error"):
            return self.Output(target=data.target, success=False, error=raw["error"])
        return self.Output(target=data.target, success=True, hosts=raw.get("hosts", []))

    async def run(self, data: Input) -> Output:
        job_id = await submit_job(self.scan_template, self.build_scan_params(data))
        result = await wait_for_result(job_id, timeout=self.timeout_seconds - 5)
        if result is None:
            return self.Output(target=data.target, success=False, error="Scan-Timeout oder Scanner nicht erreichbar")
        return self.parse_scan_result(data, result)

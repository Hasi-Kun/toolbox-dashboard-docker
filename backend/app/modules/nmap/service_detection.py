from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.nmap.common import NmapHost, validate_scan_target

MAX_PORTS = 20


@register_module
class NmapServiceDetectionModule(ToolModule):
    slug = "nmap-service-detection"
    category = "nmap"
    name = "Service Detection"
    description = f"Ermittelt Dienst- und Versionsinformationen fuer bis zu {MAX_PORTS} Ports (nmap -sV)."
    is_active_scan = True
    timeout_seconds = 75
    scan_template = "service-detection"

    class Input(BaseModel):
        target: str
        ports: list[int]

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            return validate_scan_target(v)

        @field_validator("ports")
        @classmethod
        def validate_ports(cls, v: list[int]) -> list[int]:
            if not v:
                raise ValueError("Mindestens ein Port erforderlich")
            if len(v) > MAX_PORTS:
                raise ValueError(f"Maximal {MAX_PORTS} Ports pro Anfrage")
            for port in v:
                if not (1 <= port <= 65535):
                    raise ValueError(f"Ungueltiger Port: {port}")
            return v

    class Output(BaseModel):
        target: str
        success: bool
        hosts: list[NmapHost] = []
        error: str | None = None

    def build_scan_params(self, data: Input) -> dict:
        return {"target": data.target, "ports": data.ports}

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

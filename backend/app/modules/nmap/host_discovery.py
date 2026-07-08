from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.nmap.common import NmapHost, validate_scan_target


@register_module
class NmapHostDiscoveryModule(ToolModule):
    slug = "nmap-host-discovery"
    category = "nmap"
    name = "Host Discovery (Ping-Scan)"
    description = "Prueft nur, ob das Ziel erreichbar ist -- ohne Ports zu scannen (nmap -sn). Schnell und unauffaellig."
    is_active_scan = True
    timeout_seconds = 25

    class Input(BaseModel):
        target: str

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            return validate_scan_target(v)

    class Output(BaseModel):
        target: str
        success: bool
        hosts: list[NmapHost] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        job_id = await submit_job("host-discovery", {"target": data.target})
        result = await wait_for_result(job_id, timeout=self.timeout_seconds - 5)

        if result is None:
            return self.Output(target=data.target, success=False, error="Scan-Timeout oder Scanner nicht erreichbar")
        if result.get("error"):
            return self.Output(target=data.target, success=False, error=result["error"])
        return self.Output(target=data.target, success=True, hosts=result.get("hosts", []))

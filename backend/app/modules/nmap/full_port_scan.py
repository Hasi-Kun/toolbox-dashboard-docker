from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.nmap.common import NmapHost, validate_scan_target


@register_module
class NmapFullPortScanModule(ToolModule):
    slug = "nmap-full-port-scan"
    category = "nmap"
    name = "Vollstaendiger Port-Scan"
    description = (
        "Scannt ALLE 65535 TCP-Ports statt nur der gaengigsten (nmap -p-) -- deutlich gruendlicher, "
        "aber auch deutlich langsamer als Quick-/Top-Ports-Scan. Kann mehrere Minuten dauern."
    )
    is_active_scan = True
    timeout_seconds = 300

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
        job_id = await submit_job("full-port-scan", {"target": data.target})
        result = await wait_for_result(job_id, timeout=self.timeout_seconds - 5)

        if result is None:
            return self.Output(target=data.target, success=False, error="Scan-Timeout oder Scanner nicht erreichbar")
        if result.get("error"):
            return self.Output(target=data.target, success=False, error=result["error"])
        return self.Output(target=data.target, success=True, hosts=result.get("hosts", []))

from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.nmap.common import NmapHost, validate_scan_target


@register_module
class NmapTopPortsModule(ToolModule):
    slug = "nmap-top-ports"
    category = "nmap"
    name = "Top Ports"
    description = "Scannt die N haeufigsten TCP-Ports (konfigurierbar, max. 1000)."
    is_active_scan = True
    timeout_seconds = 60
    scan_template = "top-ports"

    class Input(BaseModel):
        target: str
        count: int = 100

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            return validate_scan_target(v)

        @field_validator("count")
        @classmethod
        def validate_count(cls, v: int) -> int:
            return max(1, min(v, 1000))

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

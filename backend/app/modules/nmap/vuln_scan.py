from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.nmap.common import NmapHost, validate_scan_target


@register_module
class NmapVulnScanModule(ToolModule):
    slug = "nmap-vuln-scan"
    category = "nmap"
    name = "Vulnerability Scan (NSE)"
    description = (
        "Nutzt nmaps eigene, mitgelieferte 'vuln'-Script-Kategorie (bekannte, read-only Pruefungen "
        "auf verbreitete Schwachstellen) -- keine frei waehlbaren NSE-Scripts, nur diese feste "
        "Kategorie. Nur fuer Systeme, fuer die eine Erlaubnis zum Testen besteht."
    )
    is_active_scan = True
    requires_admin = True
    timeout_seconds = 180

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
        job_id = await submit_job("vuln-scan", {"target": data.target})
        result = await wait_for_result(job_id, timeout=self.timeout_seconds - 5)

        if result is None:
            return self.Output(target=data.target, success=False, error="Scan-Timeout oder Scanner nicht erreichbar")
        if result.get("error"):
            return self.Output(target=data.target, success=False, error=result["error"])
        return self.Output(target=data.target, success=True, hosts=result.get("hosts", []))

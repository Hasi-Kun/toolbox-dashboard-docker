from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.nmap.common import validate_scan_target


class NiktoFinding(BaseModel):
    id: str | None = None
    method: str | None = None
    url: str | None = None
    message: str | None = None
    references: str | None = None


@register_module
class NiktoScanModule(ToolModule):
    slug = "nikto-scan"
    category = "nmap"
    name = "Nikto Web Scanner"
    description = (
        "Aktiver Webserver-Scan mit Nikto -- ueber 6000 Tests auf bekannte Fehlkonfigurationen, "
        "veraltete Software und riskante Dateien/Pfade. Nur fuer Systeme, die du besitzt oder fuer "
        "die du eine ausdrueckliche Erlaubnis zum Testen hast -- Nikto erzeugt tausende Anfragen "
        "und ist fuer IDS/Log-Monitoring leicht erkennbar. Nur fuer Administratoren."
    )
    is_active_scan = True
    requires_admin = True
    timeout_seconds = 210

    class Input(BaseModel):
        target: str

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            return validate_scan_target(v)

    class Output(BaseModel):
        target: str
        success: bool
        host: str | None = None
        ip: str | None = None
        port: str | None = None
        banner: str | None = None
        findings: list[NiktoFinding] = []
        finding_count: int = 0
        error: str | None = None

    async def run(self, data: Input) -> Output:
        job_id = await submit_job("nikto", {"target": data.target})
        result = await wait_for_result(job_id, timeout=self.timeout_seconds - 5)

        if result is None:
            return self.Output(target=data.target, success=False, error="Scan-Timeout oder Scanner nicht erreichbar")
        if result.get("error"):
            return self.Output(target=data.target, success=False, error=result["error"])

        return self.Output(
            target=data.target, success=True,
            host=result.get("host"), ip=result.get("ip"), port=result.get("port"), banner=result.get("banner"),
            findings=[NiktoFinding(**f) for f in result.get("findings", [])],
            finding_count=result.get("finding_count", 0),
        )

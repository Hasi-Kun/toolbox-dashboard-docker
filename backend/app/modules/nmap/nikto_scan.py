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
    scan_template = "nikto"

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

    def build_scan_params(self, data: Input) -> dict:
        return {"target": data.target}

    def parse_scan_result(self, data: Input, raw: dict) -> Output:
        if raw.get("error"):
            return self.Output(target=data.target, success=False, error=raw["error"])
        return self.Output(
            target=data.target, success=True,
            host=raw.get("host"), ip=raw.get("ip"), port=raw.get("port"), banner=raw.get("banner"),
            findings=[NiktoFinding(**f) for f in raw.get("findings", [])],
            finding_count=raw.get("finding_count", 0),
        )

    async def run(self, data: Input) -> Output:
        job_id = await submit_job(self.scan_template, self.build_scan_params(data))
        result = await wait_for_result(job_id, timeout=self.timeout_seconds - 5)
        if result is None:
            return self.Output(target=data.target, success=False, error="Scan-Timeout oder Scanner nicht erreichbar")
        return self.parse_scan_result(data, result)

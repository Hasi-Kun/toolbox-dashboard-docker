"""testssl.sh -- gruendlicher TLS/SSL-Pruefer, der gezielt auf bekannte
Schwachstellen testet (Heartbleed, POODLE, ROBOT, DROWN, LOGJAM,
Ticketbleed, CCS-Injection, BEAST, FREAK, LUCKY13, SWEET32 u.a.) --
deutlich gruendlicher als das eigene tls-cipher-audit-Tool, das nur
Protokollversionen/Cipher-Suiten prueft.
"""

from pydantic import BaseModel, field_validator

from app.core.scan_queue import submit_job, wait_for_result
from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip


class TestsslVulnerability(BaseModel):
    id: str | None = None
    severity: str | None = None
    finding: str | None = None
    cve: str | None = None
    cwe: str | None = None
    vulnerable: bool = False


class TestsslFinding(BaseModel):
    id: str | None = None
    severity: str | None = None
    finding: str | None = None
    cve: str | None = None
    cwe: str | None = None


@register_module
class TestsslDeepScanModule(ToolModule):
    slug = "testssl-deep-scan"
    category = "testssl"
    name = "testssl.sh Deep Scan"
    description = (
        "Gruendlicher TLS/SSL-Schwachstellen-Scan mit testssl.sh -- prueft gezielt auf bekannte "
        "Schwachstellen (Heartbleed, POODLE, ROBOT, DROWN, LOGJAM, Ticketbleed, CCS-Injection, "
        "BEAST, FREAK, LUCKY13, SWEET32 u.a.), nicht nur Protokolle/Cipher wie das eigene "
        "TLS-Cipher-Audit-Tool. Kann mehrere Minuten dauern. Nur fuer Administratoren."
    )
    is_active_scan = True
    requires_admin = True
    # timeout_seconds deckelt nur den alten synchronen Fallback-Pfad (siehe
    # app/modules/nmap/*.py fuer die ausfuehrliche Begruendung der
    # Verantwortungsaufteilung) -- die tatsaechliche Obergrenze fuer den
    # Polling-Pfad liegt beim Scanner-Container selbst.
    timeout_seconds = 300
    scan_template = "testssl"

    class Input(BaseModel):
        target: str
        port: int = 443

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiger Host")
            return v

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            if not (1 <= v <= 65535):
                raise ValueError("Ungueltiger Port")
            return v

    class Output(BaseModel):
        target: str
        port: int
        success: bool
        findings: list[TestsslFinding] = []
        vulnerabilities: list[TestsslVulnerability] = []
        severity_counts: dict[str, int] = {}
        vulnerable_count: int = 0
        error: str | None = None

    def build_scan_params(self, data: Input) -> dict:
        return {"target": data.target, "port": data.port}

    def parse_scan_result(self, data: Input, raw: dict) -> Output:
        if raw.get("error"):
            return self.Output(target=data.target, port=data.port, success=False, error=raw["error"])

        vulnerabilities = [TestsslVulnerability(**v) for v in raw.get("vulnerabilities", [])]
        return self.Output(
            target=data.target, port=data.port, success=True,
            findings=[TestsslFinding(**f) for f in raw.get("findings", [])],
            vulnerabilities=vulnerabilities,
            severity_counts=raw.get("severity_counts", {}),
            vulnerable_count=sum(1 for v in vulnerabilities if v.vulnerable),
        )

    async def run(self, data: Input) -> Output:
        job_id = await submit_job(self.scan_template, self.build_scan_params(data))
        result = await wait_for_result(job_id, timeout=self.timeout_seconds - 5)
        if result is None:
            return self.Output(target=data.target, port=data.port, success=False, error="Scan-Timeout oder Scanner nicht erreichbar")
        return self.parse_scan_result(data, result)

import re

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip
from app.modules.network.common import run_subprocess

# WHOIS-Formate variieren stark je Registrar/RIR -- best effort, case-insensitive.
_FIELD_PATTERNS = {
    "registrar": re.compile(r"^Registrar:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "creation_date": re.compile(r"^(?:Creation Date|created):\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "expiry_date": re.compile(r"^(?:Registry Expiry Date|Expiry Date|paid-till):\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "name_servers": re.compile(r"^Name Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
}


@register_module
class WhoisModule(ToolModule):
    slug = "whois"
    category = "network"
    name = "Whois"
    description = "Fragt Registrierungsdaten fuer eine Domain oder IP ab."
    is_active_scan = False
    timeout_seconds = 10

    class Input(BaseModel):
        target: str

        @field_validator("target")
        @classmethod
        def validate_target(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiges Ziel (Domain oder IP erwartet)")
            return v

    class Output(BaseModel):
        target: str
        success: bool
        registrar: str | None
        creation_date: str | None
        expiry_date: str | None
        name_servers: list[str]
        raw_output: str
        error: str | None

    async def run(self, data: Input) -> Output:
        result = await run_subprocess(["whois", data.target], timeout=self.timeout_seconds)

        if result["error"]:
            return self.Output(
                target=data.target, success=False, registrar=None, creation_date=None,
                expiry_date=None, name_servers=[], raw_output="", error=result["error"],
            )

        output = result["stdout"]
        registrar_match = _FIELD_PATTERNS["registrar"].search(output)
        creation_match = _FIELD_PATTERNS["creation_date"].search(output)
        expiry_match = _FIELD_PATTERNS["expiry_date"].search(output)
        name_servers = [m.group(1).strip() for m in _FIELD_PATTERNS["name_servers"].finditer(output)]

        return self.Output(
            target=data.target,
            success=True,
            registrar=registrar_match.group(1).strip() if registrar_match else None,
            creation_date=creation_match.group(1).strip() if creation_match else None,
            expiry_date=expiry_match.group(1).strip() if expiry_match else None,
            name_servers=name_servers,
            raw_output=output,
            error=None,
        )

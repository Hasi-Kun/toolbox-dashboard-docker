from pydantic import BaseModel

from app.modules.dns.common import is_valid_hostname, is_valid_ip


def validate_scan_target(v: str) -> str:
    v = v.strip().rstrip(".")
    if not (is_valid_hostname(v) or is_valid_ip(v)):
        raise ValueError("Ungueltiges Ziel (Hostname oder IP erwartet)")
    return v


class NmapPort(BaseModel):
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


class NmapHost(BaseModel):
    address: str
    status: str
    ports: list[NmapPort] = []
    os_guesses: list[str] = []

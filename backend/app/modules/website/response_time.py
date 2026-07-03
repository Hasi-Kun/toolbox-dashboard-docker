import time

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip


@register_module
class ResponseTimeModule(ToolModule):
    slug = "response-time"
    category = "website"
    name = "Response Time"
    description = "Misst Time-to-First-Byte und Gesamtladezeit einer Seite."
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip("/")
            for prefix in ("https://", "http://"):
                if v.startswith(prefix):
                    v = v[len(prefix):]
            v = v.split("/")[0]
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        success: bool
        status_code: int | None = None
        ttfb_ms: float | None = None
        total_time_ms: float | None = None
        content_size_bytes: int | None = None
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = f"https://{data.domain}/"
        start = time.perf_counter()
        ttfb_ms: float | None = None
        content_size = 0

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True, verify=False) as client:
                async with client.stream("GET", url, headers={"User-Agent": "Toolbox-ResponseTime/1.0"}) as response:
                    ttfb_ms = (time.perf_counter() - start) * 1000
                    async for chunk in response.aiter_bytes():
                        content_size += len(chunk)
                    status_code = response.status_code
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        total_ms = (time.perf_counter() - start) * 1000

        warnings: list[str] = []
        if ttfb_ms and ttfb_ms > 800:
            warnings.append(f"TTFB von {ttfb_ms:.0f}ms ist hoch -- Nutzer erwarten meist unter 200-600ms.")

        return self.Output(
            domain=data.domain, success=True, status_code=status_code,
            ttfb_ms=round(ttfb_ms, 1) if ttfb_ms else None,
            total_time_ms=round(total_ms, 1),
            content_size_bytes=content_size, warnings=warnings, error=None,
        )

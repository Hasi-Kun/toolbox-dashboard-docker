import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip
from app.modules.security.common import build_client

# (Header-Name, Gewichtung im Score, Erklaerung bei Fehlen)
_CHECKED_HEADERS: list[tuple[str, int, str]] = [
    ("strict-transport-security", 20, "HSTS fehlt -- Browser koennen auf HTTP zurueckfallen."),
    ("content-security-policy", 20, "Keine CSP -- kein Schutz gegen XSS/Injection auf Header-Ebene."),
    ("x-content-type-options", 15, "X-Content-Type-Options fehlt -- MIME-Sniffing moeglich."),
    ("x-frame-options", 15, "X-Frame-Options fehlt -- Clickjacking-Schutz fehlt (falls CSP frame-ancestors auch fehlt)."),
    ("referrer-policy", 10, "Referrer-Policy fehlt -- volle URL wird ggf. an Dritte weitergegeben."),
    ("permissions-policy", 10, "Permissions-Policy fehlt -- Browser-Features nicht eingeschraenkt."),
]
_MAX_SCORE = sum(weight for _, weight, _ in _CHECKED_HEADERS) + 10  # +10 fuer "kein Server-Header"


def _compute_grade(score: int, max_score: int) -> str:
    if max_score == 0:
        return "F"
    percent = (score / max_score) * 100
    if percent >= 100:
        return "A+"
    if percent >= 90:
        return "A"
    if percent >= 80:
        return "B"
    if percent >= 65:
        return "C"
    if percent >= 50:
        return "D"
    return "F"


@register_module
class SecurityHeadersModule(ToolModule):
    slug = "security-headers"
    category = "security"
    name = "Security Header Check"
    description = "Prueft sicherheitsrelevante HTTP-Response-Header und vergibt einen Score inkl. Note (A+ bis F, wie securityheaders.com)."
    is_active_scan = False
    timeout_seconds = 10

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
        score: int | None = None
        max_score: int = _MAX_SCORE
        grade: str | None = None
        present_headers: dict[str, str] = {}
        missing_headers: list[str] = []
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        url = f"https://{data.domain}/"
        try:
            async with build_client(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        present: dict[str, str] = {}
        missing: list[str] = []
        warnings: list[str] = []
        score = 0

        for header, weight, warning in _CHECKED_HEADERS:
            if header in headers_lower:
                present[header] = headers_lower[header]
                score += weight
            else:
                missing.append(header)
                warnings.append(warning)

        if "server" not in headers_lower and "x-powered-by" not in headers_lower:
            score += 10
        else:
            if "server" in headers_lower:
                present["server"] = headers_lower["server"]
                warnings.append(f"Server-Header verraet Software-Version: {headers_lower['server']}")
            if "x-powered-by" in headers_lower:
                present["x-powered-by"] = headers_lower["x-powered-by"]
                warnings.append(f"X-Powered-By verraet Technologie: {headers_lower['x-powered-by']}")

        return self.Output(
            domain=data.domain,
            success=True,
            status_code=response.status_code,
            score=score,
            grade=_compute_grade(score, _MAX_SCORE),
            present_headers=present,
            missing_headers=missing,
            warnings=warnings,
            error=None,
        )

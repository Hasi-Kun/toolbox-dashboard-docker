"""Prueft Set-Cookie-Header einer Website auf fehlende Sicherheits-Flags
(Secure, HttpOnly, SameSite) -- rein passiver einzelner GET-Request.
"""

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip


class CookieAnalysis(BaseModel):
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    issues: list[str] = []


@register_module
class CookieSecurityAnalyzerModule(ToolModule):
    slug = "cookie-security-analyzer"
    category = "security"
    name = "Cookie-Security-Analyse"
    description = (
        "Prueft alle Set-Cookie-Header einer Website auf fehlende Sicherheits-Flags (Secure, "
        "HttpOnly, SameSite) -- fehlende Flags erleichtern Session-Hijacking (kein Secure/HttpOnly) "
        "oder CSRF-Angriffe (kein/laxes SameSite)."
    )
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
        cookies: list[CookieAnalysis] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = await client.get(f"https://{data.domain}/")
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        raw_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        analyses = []
        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=", 1)[0] if parts else "?"
            lower_parts = [p.lower() for p in parts[1:]]

            secure = any(p == "secure" for p in lower_parts)
            http_only = any(p == "httponly" for p in lower_parts)
            same_site_value = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), None)

            issues = []
            if not secure:
                issues.append("Kein 'Secure'-Flag -- Cookie kann auch unverschluesselt per HTTP uebertragen werden.")
            if not http_only:
                issues.append("Kein 'HttpOnly'-Flag -- per JavaScript (z.B. bei XSS) auslesbar.")
            if not same_site_value:
                issues.append("Kein 'SameSite'-Attribut gesetzt -- Browser-Standardverhalten variiert, explizit setzen empfohlen.")
            elif same_site_value.lower() == "none" and not secure:
                issues.append("SameSite=None ohne Secure-Flag ist ungueltig -- moderne Browser verwerfen dieses Cookie.")

            analyses.append(CookieAnalysis(
                name=name, secure=secure, http_only=http_only, same_site=same_site_value, issues=issues,
            ))

        return self.Output(domain=data.domain, success=True, cookies=analyses)

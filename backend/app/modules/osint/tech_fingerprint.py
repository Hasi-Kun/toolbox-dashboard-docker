import re

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname

_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", "cloudflare", "Cloudflare"),
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "microsoft-iis", "Microsoft IIS"),
    ("server", "litespeed", "LiteSpeed"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express (Node.js)"),
    ("x-generator", "wordpress", "WordPress"),
    ("x-drupal-cache", "", "Drupal"),
    ("x-varnish", "", "Varnish Cache"),
]

_BODY_SIGNATURES: list[tuple[str, str]] = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"/sites/default/files|Drupal\.settings", "Drupal"),
    (r"Joomla!", "Joomla"),
    (r"shopify", "Shopify"),
    (r"cdn\.shopify\.com", "Shopify"),
    (r"woocommerce", "WooCommerce"),
    (r"typo3", "TYPO3"),
    (r"react-dom|__NEXT_DATA__", "React / Next.js"),
    (r"ng-version=", "Angular"),
    (r"vue\.js|__VUE__", "Vue.js"),
    (r"google-site-verification", "Google Search Console verifiziert"),
    (r"gtag\(|google-analytics\.com|googletagmanager\.com", "Google Analytics/Tag Manager"),
    (r"hs-scripts\.com|hubspot", "HubSpot"),
    (r"matomo\.js|piwik\.js", "Matomo/Piwik Analytics"),
]


@register_module
class TechFingerprintModule(ToolModule):
    slug = "tech-fingerprint"
    category = "osint"
    name = "Web Technology Fingerprint"
    description = (
        "Erkennt CMS/Framework/Analytics-Hinweise einer Website anhand von HTTP-Headern und "
        "Seiteninhalt (einfache, transparente Signaturen -- keine externe Fingerprint-Datenbank)."
    )
    is_active_scan = False
    timeout_seconds = 12

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
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        success: bool
        final_url: str | None = None
        server_header: str | None = None
        detected_technologies: list[str] = []
        response_headers: dict[str, str] = {}
        error: str | None = None

    async def run(self, data: Input) -> Output:
        detected: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = await client.get(
                    f"https://{data.domain}", headers={"User-Agent": "Mozilla/5.0 (compatible; Toolbox-Fingerprint/1.0)"}
                )
        except httpx.HTTPError as exc:
            return self.Output(domain=data.domain, success=False, error=str(exc))

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        for header_name, pattern, tech in _HEADER_SIGNATURES:
            value = headers_lower.get(header_name, "")
            if pattern == "" and header_name in headers_lower:
                detected.add(tech)
            elif pattern and pattern.lower() in value.lower():
                detected.add(tech)

        body_sample = response.text[:200_000]
        for pattern, tech in _BODY_SIGNATURES:
            if re.search(pattern, body_sample, re.IGNORECASE):
                detected.add(tech)

        return self.Output(
            domain=data.domain, success=True, final_url=str(response.url),
            server_header=headers_lower.get("server"),
            detected_technologies=sorted(detected),
            response_headers=dict(response.headers),
            error=None,
        )
